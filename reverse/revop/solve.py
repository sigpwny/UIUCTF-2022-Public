import onnx_graphsurgeon as gs
import numpy as np
import onnx
import pwnlib.tubes
from pwn import *
from base64 import b64encode

graph = gs.import_onnx(onnx.load("model_dist.onnx"))

customop_1 = [node for node in graph.nodes if node.op == "customop_1"][0]
customop_2 = [node for node in graph.nodes if node.op == "customop_2"][0]
customop_3 = [node for node in graph.nodes if node.op == "customop_3"][0]

parent_gemm = customop_1.i()

parent_gemm_out = gs.Variable("parent_gemm_out", dtype=np.float32)
parent_gemm.outputs = [parent_gemm_out]

cos_out = gs.Variable("cos_out_add", dtype=np.float32)
cos_op = gs.Node(op="Cos", inputs=parent_gemm.outputs, outputs=[cos_out])

sin_out = gs.Variable("sin_out_add", dtype=np.float32)
sin_op = gs.Node(op="Sin", inputs=parent_gemm.outputs, outputs=[sin_out])

add_out = gs.Variable(name="add_out", dtype=np.float32)
add_op = gs.Node(op="Add", inputs=[
                 cos_out, sin_out], outputs=customop_1.outputs)

customop_1.outputs.clear()

graph.nodes.append(cos_op)
graph.nodes.append(sin_op)
graph.nodes.append(add_op)

add_op.outputs = [add_out]

tanh_out = gs.Variable("tanh_out", dtype=np.float32)
tanh_op = gs.Node(op="Tanh", inputs=add_op.outputs, outputs=[tanh_out])

sub_out = gs.Variable("sub_out", dtype=np.float32)
sub_op = gs.Node(op="Sub", inputs=[add_op.outputs[0], tanh_op.outputs[0]],
                   outputs=customop_2.outputs)

customop_2.outputs.clear()

graph.nodes.append(tanh_op)
graph.nodes.append(sub_op)

sub_op.outputs = [sub_out]

lrelu_out = gs.Variable("lrelu_out", dtype=np.float32)
lrelu_op = gs.Node(op="LeakyRelu", inputs=sub_op.outputs,
                outputs=customop_3.outputs)

customop_3.outputs.clear()
graph.nodes.append(lrelu_op)


graph.cleanup().toposort()

onnx.save(gs.export_onnx(graph), "model_solved.onnx")
with open('model_solved.onnx', 'rb') as f:
    data = f.read()

r = pwnlib.tubes.remote.remote('revop.chal.uiuc.tf', 1337)

r.recvuntil(b'file:')

encoded = b64encode(data)
r.sendline(encoded)

print(r.recvuntil(b'uiuctf{') + r.recvuntil(b'}'))


exit(0)
