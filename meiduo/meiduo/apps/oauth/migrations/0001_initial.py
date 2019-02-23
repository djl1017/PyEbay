# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2019-02-23 03:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='OAuthSinaUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='数据创建时间')),
                ('update_time', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('access_token', models.CharField(db_index=True, max_length=64, verbose_name='微博用户唯一标识')),
            ],
            options={
                'db_table': 'tb_sina_auth',
                'verbose_name_plural': '微博登陆用户数据',
                'verbose_name': '微博登陆用户数据',
            },
        ),
        migrations.CreateModel(
            name='QQAuthUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='数据创建时间')),
                ('update_time', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('openid', models.CharField(db_index=True, max_length=64, verbose_name='QQ用户唯一标识')),
            ],
            options={
                'db_table': 'tb_auth_qq',
                'verbose_name_plural': 'QQ登录用户数据',
                'verbose_name': 'QQ登录用户数据',
            },
        ),
    ]
