import ctypes
import re

macros = {}
loaded_dlls = {}

def tokenize(source):
    source = re.sub(r'#.*', '', source)
    token_pattern = r'"(?:[^"\\]|\\.)*"|[^\s"()]+|[()]'
    tokens = re.findall(token_pattern, source)
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

    def parse_condition(index):
        left, index = parse_expression(index)
        while index < len(tokens) and tokens[index] in {"==", "!=", "<", "<=", ">", ">=", "and", "or"}:
            operator = tokens[index]
            right, index = parse_expression(index + 1)
            left = {'left': left, 'operator': operator, 'right': right}
        return left, index

    def parse_statement(index):
        token = tokens[index]
        print(f"Parsing token: {token}")
        if token == 'macro':
            macro_name = tokens[index + 1]
            try:
                macro_body, index = _parse_block(index + 2)
            except:
                macro_body, index = parse_expression(index + 2)
            macros[macro_name] = macro_body
            return None, index + 1
        elif token in macros:
            return {'type': 'macro', 'body': macros[token]}, index + 1
        elif token == 'load':
            dll_name = tokens[index + 1]
            if dll_name in macros:
                dll_name = macros[dll_name]
            loaded_dlls[dll_name] = ctypes.WinDLL(dll_name.strip('"'))
            return None, index + 2
        elif token == 'if':
            index += 1
            condition, index = parse_condition(index)
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
            if dll in macros:
                dll = macros[dll]
            func = tokens[index + 2]
            if func in macros:
                func = macros[func]
            args = []
            i = index + 3
            while i < len(tokens) and tokens[i] != 'endcall':
                args.append(tokens[i])
                i += 1
            return {'type': 'call', 'dll': dll, 'function': func, 'args': args}, i + 1  # skip "endcall"
        elif token == 'return_value':
            # return_value is a runtime calculated value
            return {'type': 'return'}, index + 1
        else:
            raise SyntaxError(f"Unknown statement: {token}")
    
    def _parse_block(index):
        block = []
        while index < len(tokens):
            if tokens[index] in {'else', 'end'}:
                break
            stmt, index = parse_statement(index)
            if stmt is not None:
                block.append(stmt)
        return block, index

    block = []
    def parse_block(index):
        while index < len(tokens):
            if tokens[index] in {'else', 'end'}:
                break
            stmt, index = parse_statement(index)
            if stmt is not None:
                block.append(stmt)
        return block, index

    return parse_block(0)[0]

return_value = None
class Interpreter:
    def eval(self, ast):
        global return_value
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
            return_value = func(*args)
            print("Executed function: " + function_name.strip() + "\n-   Return Value: " + str(return_value))
            
        elif ast['type'] == 'macro':
            self.eval(ast['body'])

        elif ast['type'] == 'return':
            pass

        else:
            raise RuntimeError(f"Unknown AST node type: {ast['type']}")

    def _evaluate_condition(self, condition):
        if isinstance(condition, dict):
            left = self._evaluate_condition(condition['left'])
            right = self._evaluate_condition(condition['right'])
            operator = condition['operator']
            if operator == '==':
                return left == right
            elif operator == '!=':
                return left != right
            elif operator == '<':
                return left < right
            elif operator == '<=':
                return left <= right
            elif operator == '>':
                return left > right
            elif operator == '>=':
                return left >= right
            elif operator == 'and':
                return left and right
            elif operator == 'or':
                return left or right
        elif condition == 'return_value':
            return return_value
        elif isinstance(condition, str) and condition == "NULL":
            return False
        elif condition > 1:
            return condition
        return bool(int(condition))

    def _convert_arg(self, arg):
        if arg in macros:
            return macros[arg]
        elif arg.isdigit():
            return int(arg)
        elif arg.startswith('"') and arg.endswith('"'):
            return arg.strip('"').encode('utf-8')
        elif arg == "NULL":
            return None
        elif arg == "return_value":
            return return_value
        else:
            raise ValueError(f"Unknown argument type: {arg}")


interpreter = Interpreter()
with open("test.txt", 'r') as file:
    interpreter.eval(parse(tokenize(file.read())))
