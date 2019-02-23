from django.db import models

from meiduo.utils.models import BaseModel
from users.models import User


# Create your models here.
class QQAuthUser(BaseModel):
    user = models.ForeignKey(User, verbose_name='QQ登陆关联的用户', on_delete=models.CASCADE)
    openid = models.CharField(verbose_name='QQ用户唯一标识', db_index=True, max_length=64)

    class Meta:
        db_table = 'tb_auth_qq'
        verbose_name = 'QQ登录用户数据'
        verbose_name_plural = verbose_name


class OAuthSinaUser(BaseModel):
    user = models.ForeignKey(User, verbose_name='微博登陆关联的用户', on_delete=models.CASCADE)
    access_token = models.CharField(verbose_name='微博用户唯一标识', db_index=True, max_length=64)

    class Meta:
        db_table = 'tb_sina_auth'
        verbose_name = '微博登陆用户数据'
        verbose_name_plural = verbose_name
