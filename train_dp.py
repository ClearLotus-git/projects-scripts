import argparse
import json

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

from opacus import PrivacyEngine
from opacus.validators import ModuleValidator
from opacus.utils.batch_memory_manager import BatchMemoryManager
from safetensors.torch import save_file


class SVHNCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
        self.conv3 = nn.Conv2d(64, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool2d(2, 2)
        self.fc1 = nn.Linear(64 * 4 * 4, 64)
        self.fc2 = nn.Linear(64, 10)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = self.pool(F.relu(self.conv3(x)))
        x = x.view(-1, 64 * 4 * 4)
        x = F.relu(self.fc1(x))
        return self.fc2(x)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    correct = 0
    total = 0

    for x, y in loader:
        x = x.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        predictions = model(x).argmax(dim=1)
        correct += (predictions == y).sum().item()
        total += y.numel()

    return correct / total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--physical-batch-size", type=int, default=64)
    parser.add_argument("--noise", type=float, default=1.0)
    parser.add_argument("--clip", type=float, default=1.0)
    parser.add_argument("--lr", type=float, default=0.003)
    parser.add_argument("--delta", type=float, default=1e-5)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--output", default="dp_model.safetensors")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}", flush=True)

    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(
            (0.4377, 0.4438, 0.4728),
            (0.1980, 0.2010, 0.1970),
        ),
    ])

    train_dataset = datasets.SVHN(
        "data", split="train", download=True, transform=transform
    )
    test_dataset = datasets.SVHN(
        "data", split="test", download=True, transform=transform
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=args.workers,
        pin_memory=device.type == "cuda",
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=256,
        shuffle=False,
        num_workers=args.workers,
        pin_memory=device.type == "cuda",
    )

    model = SVHNCNN().to(device)
    ModuleValidator.validate(model, strict=True)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    privacy_engine = PrivacyEngine(accountant="rdp")
    model, optimizer, private_loader = privacy_engine.make_private(
        module=model,
        optimizer=optimizer,
        data_loader=train_loader,
        noise_multiplier=args.noise,
        max_grad_norm=args.clip,
        poisson_sampling=True,
    )

    for epoch in range(1, args.epochs + 1):
        model.train()

        with BatchMemoryManager(
            data_loader=private_loader,
            max_physical_batch_size=args.physical_batch_size,
            optimizer=optimizer,
        ) as memory_loader:
            for x, y in memory_loader:
                x = x.to(device, non_blocking=True)
                y = y.to(device, non_blocking=True)

                optimizer.zero_grad(set_to_none=True)
                logits = model(x)
                loss = F.cross_entropy(logits, y)
                loss.backward()
                optimizer.step()

        accuracy = evaluate(model, test_loader, device)
        epsilon = privacy_engine.get_epsilon(delta=args.delta)

        print(
            f"Epoch {epoch:02d}/{args.epochs} | "
            f"test_accuracy={accuracy:.4f} | "
            f"epsilon={epsilon:.3f} | delta={args.delta}",
            flush=True,
        )

    state = {
        name: tensor.detach().cpu().contiguous()
        for name, tensor in model._module.state_dict().items()
    }

    metadata = {
        "training": "Opacus DP-SGD",
        "epsilon": str(privacy_engine.get_epsilon(delta=args.delta)),
        "delta": str(args.delta),
        "noise_multiplier": str(args.noise),
        "max_grad_norm": str(args.clip),
        "epochs": str(args.epochs),
    }

    save_file(state, args.output, metadata=metadata)

    print(f"Saved: {args.output}")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
