from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadData
from django.conf import settings


def generate_save_user_token(openid):
    """对openid 进行加密"""

    # 1. 创建序列化器对象
    serializer = Serializer(settings.SECRET_KEY, 600)
    data = {'openid': openid}

    # 2. 调用序列化器的dumps
    access_token_bytes = serializer.dumps(data)

    # 3. 将加密后的openid 放回
    return access_token_bytes.decode()


def check_save_user_token(openid):
    """对加密的openid 进行解密"""
    serializer = Serializer(settings.SECRET_KEY, 600)

    try:
        data = serializer.loads(openid)
    except BadData:
        return None
    else:
        return data.get('openid')
