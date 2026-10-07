"""UNO-aware, literal document search/replace for Writer, Calc and Impress.

Do not assume XReplaceable is implemented by the document root: Calc
exposes it on sheets, while Impress generally exposes text on shapes.
"""


def _indexed(items):
    if hasattr(items, 'getCount') and hasattr(items, 'getByIndex'):
        for index in range(items.getCount()):
            yield items.getByIndex(index)
    else:
        yield from items


def _replace_uno_target(target, find, replace):
    descriptor = target.createReplaceDescriptor()
    descriptor.SearchString = find
    descriptor.ReplaceString = replace
    descriptor.SearchRegularExpression = False
    descriptor.SearchCaseSensitive = True
    return int(target.replaceAll(descriptor))


def _replace_shape(shape, find, replace):
    # Handle group shapes, where actual text may be on a child shape.
    total = 0
    if hasattr(shape, 'getCount') and hasattr(shape, 'getByIndex'):
        for child in _indexed(shape):
            total += _replace_shape(child, find, replace)
        return total
    if hasattr(shape, 'getString') and hasattr(shape, 'setString'):
        original = shape.getString()
        if isinstance(original, str):
            count = original.count(find)
            if count:
                shape.setString(original.replace(find, replace))
            return count
    if hasattr(shape, 'String'):
        original = shape.String
        if isinstance(original, str):
            count = original.count(find)
            if count:
                shape.String = original.replace(find, replace)
            return count
    return 0


def replace_document_text(document, find, replace):
    """Replace exact, case-sensitive text and return a replacement count.

    For Impress text shapes, writing the resulting text may reset character-level
    formatting in that shape. Writer and Calc use the native XReplaceable API.
    Calc native replaceAll counts affected cells; Writer and Impress normally
    count text matches. Unsupported types raise instead of claiming success.
    """
    if not isinstance(find, str) or not find:
        raise ValueError('find must be a nonempty string')
    if not isinstance(replace, str):
        raise ValueError('replace must be a string')
    if hasattr(document, 'createReplaceDescriptor') and hasattr(document, 'replaceAll'):
        return _replace_uno_target(document, find, replace)
    if hasattr(document, 'getSheets'):
        return sum(
            _replace_uno_target(sheet, find, replace)
            for sheet in _indexed(document.getSheets())
        )
    if hasattr(document, 'getDrawPages'):
        return sum(
            _replace_shape(shape, find, replace)
            for page in _indexed(document.getDrawPages())
            for shape in _indexed(page)
        )
    raise TypeError('This LibreOffice document does not expose a supported replacement surface')
