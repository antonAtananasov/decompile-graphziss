# Ghidra Python function to extract decompiled code and save it to a file
def decompile_c():
    # Import necessary modules from Ghidra
    import os
    from ghidra.app.decompiler import DecompInterface  # type: ignore

    # Get the current program (ProgramDB object)
    currentProgram = getCurrentProgram()  # type: ignore

    # Create the decompiler interface
    decompiler = DecompInterface()

    # Initialize the decompiler
    decompiler.openProgram(currentProgram)

    # Get a function to decompile (you can change this to decompile a specific function if needed)
    functionManager = currentProgram.getFunctionManager()
    function = functionManager.getFunctions(True)  # Get all functions in the program

    # Decompile each function and save the output
    output_file = os.environ['DECOMPILE_OUTPUT_NAMEZISS']
    function_prefix = os.environ['DECOMPILE_OUTPUT_FN_PREFIXZISS']
    with open(output_file, "w+") as f:
        for func in function:
            # Decompile the function
            decompiled = decompiler.decompileFunction(func, 30, monitor)  # type: ignore

            # Check if decompilation was successful
            if decompiled != None:
                # Write the decompiled code for this function to the file
                f.write(function_prefix + func.getName() + "\n")
                f.write(decompiled.getDecompiledFunction().getC() + "\n\n")

    print("Decompiled code has been saved to " + output_file)


if __name__ == "__main__":
    decompile_c()
