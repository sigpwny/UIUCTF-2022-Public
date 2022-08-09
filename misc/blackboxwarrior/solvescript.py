import base64
import os, io
import tempfile
import itertools

import bs4
import numpy as np
import requests
import torch
import torch.nn as nn
from PIL import Image

from torchvision import models
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch


TARGET_CLASS_NAME = 'frog'
MODEL_DIR = 'challenge/models'
imagenet_class_index = ['plane', 'car', 'bird', 'cat',
                        'deer', 'dog', 'frog', 'horse', 'ship', 'truck']
session = requests.Session()


def get_model(model_name="model.pth"):
    # Loads the model onto the cpu
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = models.efficientnet_b0(pretrained=True)
    num_ftrs = model.classifier[1].in_features
    model.classifier[1] = nn.Linear(num_ftrs, len(imagenet_class_index))
    model.load_state_dict(torch.load(os.path.join(
        MODEL_DIR, model_name), map_location=device))
    model.eval()
    return model


def bytes_to_image(img_data):
    with tempfile.NamedTemporaryFile(suffix='.png') as tmp:
        tmp.write(img_data)
        tmp.flush()
        return Image.open(tmp.name)


def get_image_to_attack(url='https://blackbox-web.chal.uiuc.tf/'):
    '''
    uses session global
    '''
    response = session.get(url)
    # req.raise_for_status() # check was successful
    text = response.text
    soup = bs4.BeautifulSoup(text, 'html.parser')
    img_tag = soup.find('img')
    img_string = img_tag['src']
    img_string[:100]
    FOUND = 'data:image/png;base64,'
    assert img_string.startswith(FOUND), img_string[:100]

    img_data = base64.b64decode(img_string[len(FOUND):])
    return bytes_to_image(img_data)


def image_to_tensor(img):
    # convert to numpy array
    tensor = np.array(img).astype(np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    tensor = torch.tensor(tensor, requires_grad=True)
    assert tensor.shape == (1, 3, 224, 224), tensor.shape
    return tensor


def image_diff(A, B):
    return ((A - B) ** 2).sum()


def fake_normalize(t):
    mean = torch.tensor([0.485, 0.456, 0.406]).reshape(-1, 1, 1)
    stdev = torch.tensor([0.229, 0.224, 0.225]).reshape(-1, 1, 1)
    return (t - mean) / stdev

def fake_denormalize(t):
    mean = torch.tensor([0.485, 0.456, 0.406]).reshape(-1, 1, 1)
    stdev = torch.tensor([0.229, 0.224, 0.225]).reshape(-1, 1, 1)
    return t * stdev + mean

def attack_image_tensor(atak_image, model):

    atak_image = fake_normalize(atak_image).detach().clone().requires_grad_(True)

    orig_image = atak_image.detach().clone()
    target = torch.tensor([imagenet_class_index.index(TARGET_CLASS_NAME)])
    optimizer = torch.optim.Adam([atak_image], lr=.00010/0.003)
    criterion = nn.CrossEntropyLoss()

    # count() is like range but infinity
    for i in itertools.count(): #range(100):
        optimizer.zero_grad()
        output = model(atak_image)

        preds = torch.argmax(output, 1)
        # print(preds)
        classify_result = imagenet_class_index[preds]
        # print(classify_result)

        if classify_result != 'horse':
            print("We found something different at iteration", i)
            if i == 0:
                print("That's weird and probably won't work")
            break

        loss = criterion(output, target)
        if i % 10 == 0:
            diff = image_diff(atak_image, orig_image)
            print(i, 'loss', loss.item(), 'diff', diff.item())
        loss.backward()
        optimizer.step()

    return fake_denormalize(atak_image)

class UnNormalize(object):
    def __init__(self, mean, std):
        self.mean = mean
        self.std = std

    def __call__(self, tensor):
        """
        Args:
            tensor (Tensor): Tensor image of size (C, H, W) to be normalized.
        Returns:
            Tensor: Normalized image.
        """
        for t, m, s in zip(tensor, self.mean, self.std):
            t.mul_(s).add_(m)
            # The normalize code -> t.sub_(m).div_(s)
        return tensor

# unorm = UnNormalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225))
# unorm(tensor)

def tensor_to_img(tensor):
    # TODO: undo Normalize operation
    # torch.lingalg.inv()
    # my_transforms = transforms.Compose([
    #                     transforms.ToTensor(),
    #                     transforms.Normalize(
    #                         [0.485, 0.456, 0.406],
    #                         [0.229, 0.224, 0.225])])
    # image = Image.open(io.BytesIO(image_bytes))
    # return my_transforms(image).unsqueeze(0)

    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)


def save_image(img, save_file='/tmp/atak.png'):
    if os.path.exists(save_file):
        os.remove(save_file)
    img.save(save_file)

# Transform image to normalize into model's bounds
def transform_image(image_bytes):
    my_transforms = transforms.Compose([#transforms.Resize(256),
                        #transforms.CenterCrop(224),
                        transforms.ToTensor(),
                        transforms.Normalize(
                            [0.485, 0.456, 0.406],
                            [0.229, 0.224, 0.225])])
    image = Image.open(io.BytesIO(image_bytes))
    return my_transforms(image).unsqueeze(0)

# Use imagehash to compare relative closeness of image (can't just allow random images to be thrown at the model...)
def get_prediction(image_bytes, model):
    inputs = transform_image(image_bytes=image_bytes)
    outputs = model(inputs)
    preds = torch.argmax(outputs, 1)
    input_image = Image.open(io.BytesIO(image_bytes))

    return imagenet_class_index[preds]

def post_adversarial_image(url='https://blackbox-web.chal.uiuc.tf/', img_file='/tmp/atak.png'):
    '''
    POSTs image to server
    '''

    files = {'file': open(img_file, 'rb')}
    response = session.post(url, files=files)

    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    div = soup.find('div', {"id": "response"})
    return div.text # the line of the response we care about, contains # of pwnies

def main():
    model = get_model()
    atak_tensor = image_to_tensor(get_image_to_attack())
    atak_tensor = attack_image_tensor(atak_tensor, model)
    img = tensor_to_img(atak_tensor)
    save_image(img)
    
    result = post_adversarial_image()
    return result

def sanity_check():
    atak_tensor = image_to_tensor(get_image_to_attack())
    save_image(tensor_to_img(atak_tensor))
    result = post_adversarial_image()
    session.cookies.clear()
    return result#[l:] # text

for x in range(100):
    r = main()
    print(r)


