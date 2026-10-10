import re
from pathlib import Path

from src.scanners import images

PINNED = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
SCANNERS_DIR = Path(__file__).resolve().parents[2] / "src" / "scanners"


def test_every_scanner_image_is_pinned_by_digest():
    for image in images.ALL_IMAGES:
        assert PINNED.match(image), f"{image} is not pinned by digest"


def test_all_three_scanner_images_are_listed():
    assert len(images.ALL_IMAGES) == 3
    assert images.GITLEAKS_IMAGE in images.ALL_IMAGES
    assert images.CHECKOV_IMAGE in images.ALL_IMAGES
    assert images.TRIVY_IMAGE in images.ALL_IMAGES


def test_scanner_modules_do_not_define_their_own_images():
    for path in SCANNERS_DIR.glob("*.py"):
        if path.name == "images.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert '_IMAGE = "' not in text, f"{path.name} defines its own image"