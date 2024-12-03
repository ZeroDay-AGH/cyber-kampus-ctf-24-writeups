from os import PathLike
from pathlib import Path

import qrcode
import numpy as np
from PIL import Image


def create_qr_code(data: any, mask_pattern: int = None) -> np.array:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=0,
        mask_pattern=mask_pattern,
    )
    qr.add_data(data)
    qr.make()
    return np.array(qr.get_matrix())


def extract_format_info(qr_array: np.array) -> dict[str, np.array]:
    size = qr_array.shape[0]

    format_info = {
        "top-left-horizontal": qr_array[8, 0:8],
        "top-left-vertical": qr_array[0:9, 8],
        "top-right-horizontal": qr_array[8, size - 8:size],
        "bottom-left-vertical": qr_array[size - 7:size, 8],
    }

    return format_info


def replace_format_info(qr_array: np.array, new_format_info: dict[str, np.array]):
    size = qr_array.shape[0]

    qr_array[8, 0:8] = new_format_info["top-left-horizontal"]
    qr_array[0:9, 8] = new_format_info["top-left-vertical"]
    qr_array[8, size - 8:size] = new_format_info["top-right-horizontal"]
    qr_array[size - 7:size, 8] = new_format_info["bottom-left-vertical"]

    return qr_array


def save_qr_image(qr_array: np.array, filename: PathLike):
    qr_img = Image.fromarray(np.invert(qr_array))
    qr_img.save(filename)


def solve(qr_file: PathLike):
    modified_qr = np.invert(np.array(Image.open(qr_file)))

    out_dir = Path.cwd() / "out"
    out_dir.mkdir(exist_ok=True)

    # check all 8 possible mask patterns
    for mask_pattern in range(8):
        temporary_qr = create_qr_code('dummy', mask_pattern=mask_pattern)
        temporary_qr_format_info = extract_format_info(temporary_qr)

        maybe_solved_qr = replace_format_info(np.copy(modified_qr), temporary_qr_format_info)

        out_file = out_dir / f"mask_{mask_pattern}.png"
        save_qr_image(maybe_solved_qr, out_file)


if __name__ == "__main__":
    solve(Path("../release/broken_glyph.png"))
