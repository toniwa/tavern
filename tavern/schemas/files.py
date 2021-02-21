import contextlib
import copy
import logging
import os
import tempfile

import jsonschema
from jsonschema import Draft7Validator
from jsonschema.validators import extend
import yaml

from tavern.plugins import load_plugins
from tavern.schemas.extensions import (
    check_parametrize_marks,
    check_strict_key,
    retry_variable,
    validate_file_spec,
    validate_json_with_ext,
    validate_request_json,
)
from tavern.util.dict_util import recurse_access_key
from tavern.util.exceptions import BadSchemaError
from tavern.util.loader import (
    BoolToken,
    FloatToken,
    IntToken,
    TypeConvertToken,
    TypeSentinel,
    load_single_document_yaml,
)

# core.yaml.safe_load = functools.partial(yaml.load, Loader=IncludeLoader)

logger = logging.getLogger(__name__)


class SchemaCache:
    """Caches loaded schemas"""

    def __init__(self):
        self._loaded = {}

    def _load_base_schema(self, schema_filename):
        try:
            return self._loaded[schema_filename]
        except KeyError:
            self._loaded[schema_filename] = load_single_document_yaml(schema_filename)

            logger.debug("Loaded schema from %s", schema_filename)

            return self._loaded[schema_filename]

    def _load_schema_with_plugins(self, schema_filename):
        mangled = "{}-plugins".format(schema_filename)

        try:
            return self._loaded[mangled]
        except KeyError:
            plugins = load_plugins()
            base_schema = copy.deepcopy(self._load_base_schema(schema_filename))

            logger.debug("Adding plugins to schema: %s", plugins)

            for p in plugins:
                try:
                    plugin_schema = p.plugin.schema
                except AttributeError:
                    # Don't require a schema
                    logger.debug("No schema defined for %s", p.name)
                else:
                    initialisations = base_schema.get("initialisations", {})
                    initialisations.update(plugin_schema.get("initialisation", {}))

                    base_schema["initialisations"] = initialisations

            self._loaded[mangled] = base_schema
            return self._loaded[mangled]

    def __call__(self, schema_filename, with_plugins):
        """Load the schema file and cache it for future use

        Args:
            schema_filename (str): filename of schema
            with_plugins (bool): Whether to load plugin schema into this schema as well

        Returns:
            dict: loaded schema
        """

        if with_plugins:
            schema = self._load_schema_with_plugins(schema_filename)
        else:
            schema = self._load_base_schema(schema_filename)

        return schema


load_schema_file = SchemaCache()


def verify_generic(to_verify, schema):
    """Verify a generic file against a given schema

    Args:
        to_verify (dict): Filename of source tests to check
        schema (dict): Schema to verify against

    Raises:
        BadSchemaError: Schema did not match
    """

    def is_str_or_bytes(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(instance, "string") or isinstance(
            instance, bytes
        )

    def is_number_or_token(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(instance, "number") or isinstance(
            instance, (IntToken, FloatToken)
        )

    def is_integer_or_token(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(instance, "integer") or isinstance(
            instance, (IntToken)
        )

    def is_boolean_or_token(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(instance, "boolean") or isinstance(
            instance, (BoolToken)
        )

    def is_object_or_sentinel(checker, instance):
        return (
            Draft7Validator.TYPE_CHECKER.is_type(instance, "object")
            or isinstance(instance, TypeSentinel)
            or isinstance(instance, TypeConvertToken)
            or instance is None
        )

    CustomValidator = extend(
        Draft7Validator,
        type_checker=Draft7Validator.TYPE_CHECKER.redefine(
            "object", is_object_or_sentinel
        )
        .redefine("string", is_str_or_bytes)
        .redefine("boolean", is_boolean_or_token)
        .redefine("integer", is_integer_or_token)
        .redefine("number", is_number_or_token),
    )
    validator = CustomValidator(schema)

    try:
        validator.validate(to_verify)
    except jsonschema.ValidationError as e:
        logger.error("e.message: %s", e.message)
        logger.error("e.context: %s", e.context)
        logger.error("e.cause: %s", e.cause)
        logger.error("e.instance: %s", e.instance)
        logger.error("e.path: %s", e.path)
        logger.error("e.schema: %s", e.schema)
        logger.error("e.schema_path: %s", e.schema_path)
        logger.error("e.validator: %s", e.validator)
        logger.error("e.validator_value: %s", e.validator_value)
        logger.exception("Error validating %s", to_verify)
        msg = "err:\n---\n" + """"\n---\n""".join([str(i) for i in e.context])
        raise BadSchemaError(msg) from e

    extra_checks = {
        "stages[*].mqtt_publish.json[]": validate_request_json,
        "stages[*].request.json[]": validate_request_json,
        "stages[*].request.data[]": validate_request_json,
        "stages[*].request.params[]": validate_request_json,
        "stages[*].request.headers[]": validate_request_json,
        "stages[*].request.save[]": validate_json_with_ext,
        "stages[*].request.files[]": validate_file_spec,
        "marks[*].parametrize[]": check_parametrize_marks,
        "stages[*].response.strict[]": validate_json_with_ext,
        "stages[*].max_retries[]": retry_variable,
        "strict": check_strict_key,
    }

    for path, func in extra_checks.items():
        data = recurse_access_key(to_verify, path)
        if data:
            if path.endswith("[]"):
                if not isinstance(data, list):
                    raise BadSchemaError

                for element in data:
                    func(element, None, path)
            else:
                func(data, None, path)


@contextlib.contextmanager
def wrapfile(to_wrap):
    """Wrap a dictionary into a temporary yaml file

    Args:
        to_wrap (dict): Dictionary to write to temporary file

    Yields:
        filename: name of temporary file object that will be destroyed at the end of the
            context manager
    """
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as wrapped_tmp:
        # put into a file
        dumped = yaml.dump(to_wrap, default_flow_style=False)
        wrapped_tmp.write(dumped.encode("utf8"))
        wrapped_tmp.close()

        try:
            yield wrapped_tmp.name
        finally:
            os.remove(wrapped_tmp.name)


def verify_tests(test_spec, with_plugins=True):
    """Verify that a specific test block is correct

    Todo:
        Load schema file once. Requires some caching of the file

    Args:
        test_spec (dict): Test in dictionary form

    Raises:
        BadSchemaError: Schema did not match
    """
    here = os.path.dirname(os.path.abspath(__file__))

    schema_filename = os.path.join(here, "tests.jsonschema.yaml")
    schema = load_schema_file(schema_filename, with_plugins)

    verify_generic(test_spec, schema)
