def graph_json():
    import os
    import json
    from ghidra.program.model.listing import Function  # type: ignore
    from ghidra.program.model.block import BasicBlockModel  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
    from ghidra.app.decompiler import DecompInterface  # type: ignore

    # Get the current program
    current_program = getCurrentProgram()  # type: ignore

    # Get the function manager
    function_manager = current_program.getFunctionManager()

    # Get all functions in the program
    functions = function_manager.getFunctions(True)

    # Create a directed graph

    # Iterate through functions
    monitor = ConsoleTaskMonitor()

    # Initialize BasicBlockModel to get the basic blocks for a function
    block_model = BasicBlockModel(current_program)
    blocks = block_model.getCodeBlocks(monitor)

    # Export relations
    block_datas = []
    for block in blocks:
        block_data = serializeBlock(monitor, block)

        block_datas.append(block_data)

    # Add code to relations
    decompiler = DecompInterface()
    decompiler.openProgram(current_program)
    function_datas = []
    for function in functions:
        function_data = serializeFunction(monitor, decompiler, function)

        function_datas.append(function_data)
        for block_data in block_datas:
            if block_data["name"] == function.getName():
                block_data.update({"function": function_data})

    # Export JSON
    output_file = os.environ["GRAPH_OUTPUT_NAMEZISS"]
    with open(output_file, "w") as f:
        json.dump(block_datas, f, indent=4)


def serializeFunction(monitor, decompiler, function):
    function_data = {
        "allVariables": [serializeVariable(var) for var in function.getAllVariables()],
        "autoParameterCount": function.getAutoParameterCount(),
        "calledFunctionsNames": [
            fn.getName() for fn in function.getCalledFunctions(monitor)
        ],
        "callFixup": function.getCallFixup(),
        "callingConventionName": function.getCallingConventionName(),
        "callingFunctions": [
            fn.getName() for fn in function.getCallingFunctions(monitor)
        ],
        "comment": function.getComment(),
        "entryPoint": str(function.getEntryPoint()),
        "localVariables": [
            serializeVariable(var) for var in function.getLocalVariables()
        ],
        "name": function.getName(),
        "parameterCount": function.getParameterCount(),
        "parameters": [serializeParameter(param) for param in function.getParameters()],
        "return": serializeParameter(function.getReturn()),
        "returnType": str(function.getReturnType()),
        "tags": [
            {"name": tag.getName(), "comment": tag.getComment()}
            for tag in function.getTags()
        ],
    }

    decompiled = decompiler.decompileFunction(function, 30, monitor)
    # Check if decompilation was successful
    if decompiled != None:
        # Write the decompiled code for this function to the file
        function_data.update(
            {
                "decompiledFunction": decompiled.getDecompiledFunction().getC(),
            }
        )

    return function_data


def serializeVariable(variable):
    result = {
        "comment": variable.getComment(),
        "dataType": str(variable.getDataType()),
        "length": variable.getLength(),
        "name": variable.getName(),
        "minAddress": str(variable.getMinAddress()),
    }
    return result


def serializeParameter(param):
    result = {
        "ordinal": param.getOrdinal(),
        "formalDataType": str(param.getFormalDataType()),
        "autoParameterType": str(param.getAutoParameterType()),
    }
    return result


def serializeBlock(monitor, block):
    block_data = {
        "addresses": [str(addr) for addr in block.getAddresses(True)],
        "addressRanges": [
            [str(addr) for addr in rng] for rng in block.getAddressRanges()
        ],
        "firstRange": [str(addr) for addr in block.getFirstRange()],
        "firstStartAddress": str(block.getFirstStartAddress()),
        "flowType": str(block.getFlowType()),
        "lastRange": [str(addr) for addr in block.getLastRange()],
        "maxAddress": str(block.getMaxAddress()),
        "minAddress": str(block.getMinAddress()),
        "modelName": block.getModel().getName(),
        "name": block.getName(),
        "startAddresses": [str(addr) for addr in block.getStartAddresses()],
        "hashCode": block.hashCode(),
    }

    for k, (iterator, num) in {
        "destinations": (
            block.getDestinations(monitor),
            block.getNumDestinations(monitor),
        ),
        "sources": (block.getSources(monitor), block.getNumSources(monitor)),
    }.items():
        data = []
        for _ in range(num):
            reference = iterator.next()
            data.append(serializeReference(reference))
        block_data.update({k: data})
    return block_data


def serializeReference(reference):
    return {
        "representation": str(reference),
        "destinationAddress": str(reference.getDestinationAddress()),
        "destinationBlockName": reference.getDestinationBlock().getName(),
        "flowType": str(reference.getFlowType()),
        "reference": str(reference.getReference()),
        "referent": str(reference.getReferent()),
        "sourceAddress": str(reference.getSourceAddress()),
        "sourceBlockName": reference.getSourceBlock().getName(),
    }


if __name__ == "__main__":
    graph_json()
