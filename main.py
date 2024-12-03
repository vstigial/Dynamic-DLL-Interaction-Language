import ctypes

macros = {}
loaded_dlls = {}

def tokenize(source):
    tokens = source.replace('\n', ' ').split()
    return tokens

def parse(tokens):
    def parse_expression(index):
        token = tokens[index]
        if token.isdigit():
            return int(token), index + 1
        elif token.startswith('"') and token.endswith('"'):
            return token[1:-1], index + 1
        else:
            return token, index + 1

    def parse_statement(index):
        token = tokens[index]
        print(f"Parsing token: {token}")
        if token == 'macro':
            macro_name = tokens[index + 1]
            macro_body, index = _parse_block(index + 2)
            macros[macro_name] = macro_body
            return None, index+1
        elif token in macros:
            return {'type': 'macro', 'body': macros[token]}, index + 1
        elif token == 'load':
            dll_name = tokens[index + 1]
            loaded_dlls[dll_name] = ctypes.WinDLL(dll_name.strip('"'))
            return None, index + 2
        elif token == 'if':
            index += 1
            condition, index = parse_expression(index)
            if tokens[index] != 'then':
                raise SyntaxError(f"Expected 'then' after condition at index {index}, found {tokens[index]}")
            index += 1
            true_branch, index = _parse_block(index)
            false_branch = None
            if tokens[index] == 'else':
                index += 1
                false_branch, index = _parse_block(index)
            if tokens[index] != 'end':
                raise SyntaxError(f"Expected 'end' after if-else block at index {index}, found {tokens[index]}")
            return {'type': 'if', 'condition': condition, 'true': true_branch, 'false': false_branch}, index + 1
        elif token == 'call':
            dll = tokens[index + 1]
            func = tokens[index + 2]
            args = []
            i = index + 3
            while i < len(tokens) and tokens[i] not in {'if', 'then', 'else', 'end'}:
                args.append(tokens[i])
                i += 1
            return {'type': 'call', 'dll': dll, 'function': func, 'args': args}, i
        else:
            raise SyntaxError(f"Unknown statement: {token}")
    
    def _parse_block(index):
        block = []
        while index < len(tokens) and tokens[index] not in {'else', 'end'}:
            stmt, index = parse_statement(index)
            if stmt is not None:
                block.append(stmt)
        return block, index

    block = []
    def parse_block(index):
        while index < len(tokens) and tokens[index] not in {'else', 'end'}:
            stmt, index = parse_statement(index)
            if stmt is not None:
                block.append(stmt)
        return block, index

    return parse_block(0)[0]

class Interpreter:
    def eval(self, ast):
        if isinstance(ast, list):
            for statement in ast:
                self.eval(statement)
        elif ast['type'] == 'if':
            condition = self._evaluate_condition(ast['condition'])
            if condition:
                self.eval(ast['true'])
            elif ast['false']:
                self.eval(ast['false'])
        elif ast['type'] == 'call':
            dll_name = ast['dll'].strip('"')
            function_name = ast['function'].strip('"')
            args = [self._convert_arg(arg) for arg in ast['args']]
            if dll_name in loaded_dlls:
                dll = loaded_dlls[dll_name]
            else:
                dll = ctypes.WinDLL(dll_name)
                loaded_dlls[dll_name] = dll
            func = getattr(dll, function_name)
            print("Executed function: " + function_name.strip() + "\n-   Return Value: " + str(func(*args)))
            
        elif ast['type'] == 'macro':
            self.eval(ast['body'])
        else:
            raise RuntimeError(f"Unknown AST node type: {ast['type']}")

    def _evaluate_condition(self, condition):
        return bool(int(condition))

    def _convert_arg(self, arg):
        if arg.isdigit():
            return int(arg)
        elif arg.startswith('"') and arg.endswith('"'):
            return arg.strip('"').encode('utf-8')
        elif arg == "NULL":
            return None
        else:
            raise ValueError(f"Unknown argument type: {arg}")


interpreter = Interpreter()
with open("test.txt", 'r') as file:
    interpreter.eval(parse(tokenize(file.read())))