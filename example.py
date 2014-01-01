
print 'hello'

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
    functionName = GetFunctionName(funcea)
    print functionName

print 'good bye'
