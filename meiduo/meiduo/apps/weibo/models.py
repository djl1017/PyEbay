from django.db import models

from meiduo.utils.models import BaseModel
from users.models import User

# Create your models here.


class WeiboAuthUser(BaseModel):
    """微博登录模型类, 共4个字段, 创建,更新字段继承于BaseModel"""

    # 外键关联 User, 在实际表里的字段是 user_id
    user = models.ForeignKey(User, verbose_name='openid关联的用户', on_delete=models.CASCADE)
    openid = models.CharField(verbose_name='QQ用户唯一标识', db_index=True, max_length=64)

    class Meta:
        db_table = 'tb_oauth_qq'
        verbose_name = 'QQ登录用户数据'
        verbose_name_plural = verbose_name

    # 注意: makemigrations 前要先注册子用户


