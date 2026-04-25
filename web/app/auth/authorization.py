def user_can_access_document(user_id, document):
    """
    Verifica se um user pode aceder a um documento.
    Regra atual: apenas o owner pode aceder.
    """
    if not document:
        return False

    return document["owner_id"] == user_id
