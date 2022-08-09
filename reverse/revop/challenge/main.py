from io import BytesIO
import base64
import onnx
import numpy as np
import onnxruntime as ort
import torch

ref_tensor = torch.randn(64, 1, 32, 32)

def to_numpy(tensor):
    return tensor.detach().cpu().numpy() if tensor.requires_grad else tensor.cpu().numpy()

def onnx_model_util_path(model_path):
    onnx_model = onnx.load(model_path)
    onnx.checker.check_model(onnx_model)
    model_proto_bytes = onnx._serialize(model_proto)
    ort_session = ort.InferenceSession(model_proto_bytes)
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(ref_tensor)}
    ort_outs = ort_session.run(None, ort_inputs)
    return ort_outs[0]

def onnx_model_util_io(model_proto):
    onnx_model = model_proto
    onnx.checker.check_model(onnx_model)
    model_proto_bytes = onnx._serialize(model_proto)
    ort_session = ort.InferenceSession(model_proto_bytes)
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(ref_tensor)}
    ort_outs = ort_session.run(None, ort_inputs)
    return ort_outs[0]


encoded = input('Input base64 onnx file:')

decoded = BytesIO(base64.b64decode(encoded.strip()))

model_proto = onnx.load_model_from_string(decoded.getvalue(), onnx.ModelProto)
np.testing.assert_allclose(onnx_model_util_io(model_proto), onnx_model_util_path("model_ref.onnx"), rtol=1e-03, atol=1e-05)

try:
    with open("/flag") as f:
        FLAG = f.read()
except FileNotFoundError:
    FLAG = "TEMP_FLAG"
print(f"PwnyOps presents the flag: {FLAG}")


