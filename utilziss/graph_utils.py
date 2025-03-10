from typing import Any


def block_list_to_node_list(blocks: list[dict], property: str) -> list[Any]:
    nodes = []

    heirarchy_keys = property.split(".")
    for block in blocks:
        block_property = find_property(heirarchy_keys, block)

        if not block_property is None:
            nodes.append(block_property)

    return nodes



def block_list_to_edge_dict(
    blocks: list[dict], source_property: str, destination_property: str
) -> dict[str:Any]:
    edges = {}

    source_heirarchy_keys = source_property.split(".")
    destination_heirarchy_keys = destination_property.split(".")
    for block in blocks:
        block_source_property = find_property(source_heirarchy_keys, block)
        block_destination_property = find_property(destination_heirarchy_keys, block)

        if not block_source_property is None and not block_destination_property is None:
            edges.update({block_source_property: block_destination_property})

    return edges


def find_property(heirarchy_keys: list[str], block: dict):
    property = block
    for i in range(len(heirarchy_keys)):
        key = heirarchy_keys[i]
        if key in property:
            property = property[key]
            if isinstance(property, list) and i < len(heirarchy_keys) - 1:
                property = [
                    find_property(heirarchy_keys[i + 1 :], prop) for prop in property
                ]
        else:
            break
    return property
