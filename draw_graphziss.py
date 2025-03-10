import os
import json
import networkx as nx
from json2html import json2html
from pyvis.network import Network
from utilziss.graph_utils import block_list_to_edge_dict
from decompile_graphziss import main as decompile_get_json
from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import HtmlFormatter


def main():
    INPUT_JSON: str | None = None or "./tmp/data.json"
    INPUT_BINARY: str | None = None or "./Tools/Easy-CrackMe-Binary-main/crackme"
    OUTPUT_DIR = "./tmp/"
    OUTPUT_HTML = "graph.html"

    defaultColors = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
    ]

    data = []
    if not INPUT_JSON is None and os.path.exists(INPUT_JSON):
        with open(INPUT_JSON, "r") as f:
            data = json.load(f)
    elif not INPUT_BINARY is None and os.path.exists(INPUT_BINARY):
        key = input(
            f"Input file {INPUT_JSON} not specified or not found. Proceed to decompile {INPUT_BINARY} to generate it? [Y/n]"
        )
        if key.lower() == "y" or len(key) == 0:
            data = decompile_get_json(INPUT_BINARY)
    else:
        print("No specified binary ot json to extract data.")

    graph_edges = block_list_to_edge_dict(
        data, "name", "destinations.destinationBlockName"
    )
    node_modelNames = block_list_to_edge_dict(data, "name", "modelName")
    node_flowTypes = block_list_to_edge_dict(data, "name", "destinations.flowType")
    node_functions = block_list_to_edge_dict(
        data, "name", "function.decompiledFunction"
    )
    node_datas = {block["name"]: block for block in data}

    for node, data in node_datas.items():
        with open(os.path.join(OUTPUT_DIR, node + ".htm"), "w+") as f:
            f.write("<html><body>")
            f.write(
                """
                    <style>
                        body {
                            background-color: #021526;
                    color: #fff;
                    font-family: Courier New;
                    }
                    </style>
                """
            )

            html = (
                json2html.convert(json.dumps(data))
                .replace("<th>decompiledFunction</th><td>", "<th>decompiledFunction</th><td><pre>")
                .replace("\n</td>", "\n</pre></td>")
            )
            f.write(html)
            f.write("</body></html>")

    allModelNames = list(set([mn for mn in node_modelNames.values()]))
    allFlowTypes = list(
        set([item for sublist in node_flowTypes.values() for item in sublist])
    )

    graph = nx.empty_graph()

    for src, dests in graph_edges.items():

        node_color = defaultColors[
            allModelNames.index(node_modelNames[src]) % len(defaultColors)
        ]

        node_title = node_modelNames[src]
        graph.add_node(
            src,
            color=node_color,
            title=node_title,
        )
        for dest in dests:
            flow_type = node_flowTypes[src][dests.index(dest)]
            edge_color = defaultColors[
                allFlowTypes.index(flow_type) % len(defaultColors)
            ]
            edge_title = flow_type
            graph.add_edge(src, dest, color=edge_color, title=edge_title)

    net = Network(
        notebook=True,
        cdn_resources="in_line",
        height="1000px",
        width="100%",
        bgcolor="#021526",
        font_color="white",  # White labels
    )

    net.from_nx(graph)
    html = net.generate_html()
    custom_js = """
        <script type="text/javascript">
            network.addEventListener('selectNode',(e)=>{window.open(e.nodes[0]+'.htm')})
        </script>
        """
    html = html.replace("</body>", custom_js + "</body>")
    with open(os.path.join(OUTPUT_DIR, OUTPUT_HTML), mode="w", encoding="utf-8") as fp:
        fp.write(html)


if __name__ == "__main__":
    main()
