"""JSON-LD processor."""

from deepdiff import DeepDiff, grep
from pyld import jsonld
from rfc3986_validator import validate_rfc3986


class JsonLdProcessorException(Exception):
    """Base exception for JSON-LD Processor."""


class JsonLdProcessor:
    """JSON-LD Processor."""

    def __init__(self, timeout: int = 100) -> None:
        """Initialize new JsonLdProcessor instance."""
        jsonld.set_document_loader(jsonld.requests_document_loader(timeout=timeout))

    def find_undefined_properties(self, document):
        """Find undefined properties."""
        undefined_properties = []
        diff = DeepDiff(document, self.compact(document))
        if "dictionary_item_removed" in diff:
            for item in diff["dictionary_item_removed"]:
                """
                Extract the last element of the path as the undefined property.
                """
                item = item.split("['")[-1].strip("']'")
                undefined_properties.append(item)

        if "type_changes" in diff:
            for item in diff["type_changes"]:
                """
                If a VC object only contains `id` and no other defined terms, 
                the object will be transformed into the id value.
                
                Here we detect if an object was changed from a dict 
                and drop the `id` value of the original dict to see which
                undefined properties were silently dropped if any.
                """
                if isinstance(diff["type_changes"][item]["old_type"], dict):
                    diff["type_changes"][item]["old_value"].pop("id", None)
                    for property in diff["type_changes"][item]["old_value"]:
                        undefined_properties.append(property)
        return undefined_properties

    def find_undefined_types(self, document):
        """Find undefined types."""
        undefined_types = []
        type_query = self.expand(document) | grep("@type", verbose_level=2)
        if "matched_paths" in type_query:
            for type_entry in type_query["matched_paths"]:
                for item in (
                    [type_query["matched_paths"][type_entry]]
                    if isinstance(type_query["matched_paths"][type_entry], str)
                    else type_query["matched_paths"][type_entry]
                ):
                    if not validate_rfc3986(item):
                        # Types that don't get compacted into a URI are undefined
                        undefined_types.append(item)
        return undefined_types

    def compact(self, document):
        """Compact json-ld document."""
        try:
            return jsonld.compact(document, document["@context"])
        except jsonld.JsonLdError as e:
            error = {}
            if isinstance(type(e.cause), jsonld.JsonLdError):
                error["type"] = e.cause.type
                error["code"] = e.cause.code
                if e.cause.type == "jsonld.InvalidUrl":
                    error["url"] = e.cause.details["url"]
            raise JsonLdProcessorException()

    def expand(self, document):
        """Expand json-ld document."""
        try:
            return jsonld.expand(document)
        except jsonld.JsonLdError as e:
            error = {}
            if isinstance(type(e.cause), jsonld.JsonLdError):
                error["type"] = e.cause.type
                error["code"] = e.cause.code
            raise JsonLdProcessorException()

    def inject_context(self, document, context):
        """Context injection."""
        document["@context"] = (
            document["@context"]
            if isinstance(document["@context"], list)
            else [document["@context"]]
        )
        if context not in document["@context"]:
            document["@context"].append(context)
        return document

    def encode_canonical_rdf(self, document):
        """Canonical RDF encoding."""
        normalized = jsonld.normalize(
            document, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
        return normalized.encode()
