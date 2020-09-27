from typing import Iterator


def format_for_xml(text: str) -> str:
    formatted = text.replace('&', '&amp;')
    return formatted


def get_lines(file_path: str) -> Iterator[str]:
    """
    Returns the lines that are not empty of a given file path.
    """
    with open(file_path, 'r') as f:
        song_names = f.read().split('\n')
        return filter(None, song_names)
