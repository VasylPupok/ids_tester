from dataclasses import dataclass

import src.attack_modules.open_api_3_parser as openapi_parser


class Property:
    def __init__(self, spec: dict):
        self.type: str = spec['type']
        self.spec: dict = spec
        if self.type == 'array' and 'items' in spec:
            items_dict = spec.get('items')
            self.items_schema: Schema = Schema(items_dict)
        elif self.type == 'object' and 'properties' in spec:
            properties_dict = spec.get('properties')
            self.object_schema: Schema = Schema(properties_dict)
        elif self.type == 'oneOf':
            self.oneOf: list[str] = [t for t in spec.get('oneOf')]


class Schema:
    def __init__(self, spec: dict):
        self.required = []
        if 'required' in spec:
            self.required: list[str] = spec['required']
        self.properties: dict[str, Property] = {name: Property(spec['properties'][name]) for name in spec['properties']}


class Parameter:
    def __init__(self, spec: dict):
        self.name = spec['name']
        self.location = spec['in']
        self.schema: dict = spec['schema']

    def get_type(self) -> str:
        return self.schema['type']


class Method:
    def __init__(self, name: str, spec: dict):
        self.name = name

        try:
            self.parameters: list[Parameter] = [Parameter(p) for p in spec['parameters']]
        except KeyError:
            self.parameters: list[Parameter] = []

        if 'required' in spec:
            self.schema: Schema = Schema(spec['requestBody']['content']['application/json']['schema'])
        else:
            self.schema = None


class Path:
    def __init__(self, url: str, openapi_spec: dict):
        self.url = url
        self.methods: list[Method] = [Method(method, openapi_spec[method]) for method in openapi_spec]


class TargetInfo:
    def __init__(self, id: str, hostname: str, open_api_path: str):
        self.id = id
        self.hostname: str = hostname
        self.openapi_parser: openapi_parser.OpenAPIParser = openapi_parser.OpenAPIParser(
            open_api_spec_path=open_api_path)

    def get_paths(self) -> list[Path]:
        paths = self.openapi_parser.get_paths()
        return [Path(url, paths[url]) for url in paths]
