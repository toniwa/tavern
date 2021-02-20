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
from tavern.schemas.extensions import validate_file_spec, validate_json_with_ext, validate_request_json
from tavern.util.exceptions import BadSchemaError
from tavern.util.loader import TypeSentinel, load_single_document_yaml

# core.yaml.safe_load = functools.partial(yaml.load, Loader=IncludeLoader)

logger = logging.getLogger(__name__)


class SchemaCache(object):
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

    def is_sentinel(checker, instance):
        return isinstance(instance, TypeSentinel)

    def is_request_object(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(
            instance, "object"
        ) and validate_request_json(instance, None, "")

    def is_request_object_with_ext(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(
            instance, "object"
        ) and validate_json_with_ext(instance, None, "")

    def is_file_object(checker, instance):
        return Draft7Validator.TYPE_CHECKER.is_type(
            instance, "object"
        ) and validate_file_spec(instance, None, "")

    CustomValidator = extend(
        Draft7Validator,
        type_checker=Draft7Validator.TYPE_CHECKER.redefine("sentinel", is_sentinel)
        .redefine("string", is_str_or_bytes)
        .redefine("request_object", is_request_object)
        .redefine("request_object_with_ext", is_request_object_with_ext)
        .redefine("file_object", is_file_object),
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
