from django_redis import get_redis_connection
from rest_framework import serializers

from oauth.models import QQAuthUser
from users.models import User
from .utils import check_save_user_token


class WeiboAuthUserSerializer(serializers.Serializer):
    """绑定用户的序列化器"""

    access_token = serializers.CharField(label="登录凭证")
    mobile = serializers.RegexField(label='手机号', regex=r'^1[3-9]\d{9}$')
    password = serializers.CharField(label='密码', min_length=8, max_length=20)
    sms_code = serializers.CharField(label='短信验证码')

    def validate(self, attrs):
        """字段联合校验"""

        # 验证openid
        access_token = attrs.get('access_token')  # 获取加密字符串
        openid = check_save_user_token(access_token)  # 解密判断
        if not openid:
            raise serializers.ValidationError('openid 无效哦')
        # 将openid 存起来, 以后用
        attrs['openid'] = openid

        # 验证短信验证码
        redis_coon = get_redis_connection('verify_codes')
        #  获取当前用户的手机号
        mobile = attrs.get('mobile')
        real_sms_code = redis_coon.get('sms_%s' % mobile)

        # 如果没有取到值从redis, 也要抛异常
        if real_sms_code is None:
            raise serializers.ValidationError('验证码过期啦')

        # 获取前端传来的 短信验证码
        sms_code = attrs.get('sms_code')

        if sms_code != real_sms_code.decode():
            raise serializers.ValidationError('验证输入错误')

        # 判断手机号是否已注册(是新用户吗)
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 异常则说明是新用户, 不做任何处理
            return attrs
        else:
            # 没有报错, 执行else, 说明该手机号已经被注册了
            # 接着判断 输入的密码是否正确
            if not user.check_password(attrs.get('password')):
                raise serializers.ValidationError('用户存在, 但密码输入错误')
            else:
                # 密码也对,
                attrs['user'] = user

        return attrs

    def create(self, validated_data):
        """将openid 和 user 进行绑定, 即将这种关系存起来"""
        user = validated_data.get("user")
        if user:
            pass
        else:
            # 首先, 存储新用户的手机号, 密码, 用户名...额,暂时用手机号代替一下吧
            user = User(
                # 注意: attrs 与 validated_data 是指向同一个参数对象哦
                # username=validated_data.get('username'),
                username=validated_data.get('mobile'),
                mobile=validated_data.get('mobile'),
                password=validated_data
            )
            # 加密
            user.set_password(validated_data.get('password'))
            user.save()  # 这种装逼写法, 提高了性能哦

        # 绑定user 和 openid
        QQAuthUser.objects.create(
            user=user,
            openid=validated_data.get('openid')

        )

        return user
