#!/usr/bin/env python
# -*- coding: utf-8 -*-

# @Time    : 2018/6/7 上午9:40
# @Author  : YouMing
# @Email   : myoueva@gmail.com
# @File    : spider_topten_netesay.py
# @Software: PyCharm
# @license : 娱网科道信息技术有限公司 copyright © 2015-2016
from __future__ import (
    print_function, unicode_literals, division, absolute_import
)
# install pycrypto
import base64
import json
import requests
import os
import sys
import codecs
import time
import hashlib
import binascii
import collections
from Cryptodome.Cipher import AES
from requests.exceptions import RequestException
from future.builtins import int, pow
from http.cookiejar import LWPCookieJar
from bs4 import BeautifulSoup


class NetEasyTopMusic(object):
    """for wang yi yun music command top 10 music data by your sign in"""

    MODULUS = ('00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7'
               'b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280'
               '104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932'
               '575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b'
               '3ece0462db0a22b8e7')
    nonce = b'0CoJUm6Qyw8W8jud'
    pub_key = '010001'
    client_token = '1_jVUMqWEPke0/1/Vu56xCmJpo5vP1grjn_SOVVDzOc78w8OKLVZ2JH7IfkjSXqgfmh'

    def __init__(self, acc, pss):
        md_create = hashlib.md5()
        md_create.update(pss.encode('utf-8'))
        self.acc = acc
        self.pss = md_create.hexdigest()
        self.header = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip,deflate,sdch',
            'Accept-Language': 'zh-CN,zh;q=0.8,gl;q=0.6,zh-TW;q=0.4',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'music.163.com',
            'Referer': 'http://music.163.com',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
        }

    def login_cell_phone(self, text):
        """
        1.手机登录form data参数：
        phone：手机号
        password：密码（需要计算出散列值）
        rememberLogin: 'true'
        :return:
        """
        # text = {
        #     'phone': self.acc,
        #     'password': self.pss,
        #     'rememberLogin': 'true'
        # }
        text = json.dumps(text).encode('utf-8')
        sec_key = NetEasyTopMusic.create_secret_key(16)
        frist_aes_key = NetEasyTopMusic.aes_encrypt(text, NetEasyTopMusic.nonce)
        enc_text = NetEasyTopMusic.aes_encrypt(frist_aes_key, sec_key)
        enc_sec_key = NetEasyTopMusic.rsa_encrypt(sec_key, NetEasyTopMusic.pub_key, NetEasyTopMusic.MODULUS)
        data = {
            'params': enc_text,
            'encSecKey': enc_sec_key
        }
        return data

    @staticmethod
    def rsa_encrypt(text, pub_key, modulus):
        text = text[::-1]
        # rs = int(codecs.encode(text.encode('utf-8'), 'hex_codec'), 16)**int(pub_key, 16) % int(modulus, 16)
        rs = pow(int(binascii.hexlify(text), 16),
                 int(pub_key, 16), int(modulus, 16))
        return format(rs, 'x').zfill(256)

    @staticmethod
    def create_secret_key(size):
        # return (''.join(map(lambda xx: (hex(ord(xx))[2:]), str(os.urandom(size)))))[0:16]
        return binascii.hexlify(os.urandom(size))[:16]

    @staticmethod
    def aes_encrypt(text, sec_key):
        """
        AES加密算法解析：
        1.AES加密的算法：AES-128-CBC，输出格式为base64
        2.AES的加密iv：0102030405060708
        3.AES的加密文本需要padding：原文本加处理后的text
        :param text:
        :param sec_key:
        :return:
        """
        pad = 16 - len(text) % 16
        text = text + bytearray([pad] * pad)
        encryptor = AES.new(sec_key, 2, b'0102030405060708')
        ciphertext = encryptor.encrypt(text)
        return base64.b64encode(ciphertext)
        # pad = 16 - len(text) % 16
        # # text = text + pad * chr(pad)
        # text = text + bytearray([pad] * pad)
        # encryptor = AES.new(sec_key, 2, b'0102030405060708')
        # enc_text = encryptor.encrypt(text)
        # base_enc_text = base64.b64encode(enc_text)
        # return base_enc_text

    def get_login_info(self):
        info_list = ['background', 'user_header_img', 'user_name', 'user_signature', 'qq_name', 'we_chat_name', 'csrf_token']
        login_info = collections.namedtuple('login_info', info_list)
        text = {
            'phone': self.acc,
            'password': self.pss,
            'rememberLogin': 'true'
        }
        data = self.login_cell_phone(text)
        try:
            response = requests.post('https://music.163.com/weapi/login/cellphone', data=data, headers=self.header)
            if response.status_code == 200:
                self.cookies = response.cookies
                self.token = response.cookies.get('__csrf', None)
                user_info = json.loads(response.text)
                if user_info:
                    background_url = user_info['profile'].get('backgroundUrl', 'http://p2.music.126.net/hV9qcHj-xDPdtsd32jaUHg==/3427177773521921.jpg')
                    user_header_img_url = user_info['profile'].get('avatarUrl', 'http://p2.music.126.net/hV9qcHj-xDPdtsd32jaUHg==/3427177773521921.jpg')
                    user_name_info = user_info['profile'].get('nickname', '猪儿虫')
                    user_sig_info = user_info['profile'].get('signature', '我是一个猪儿虫')
                    total = len(user_info['bindings'])>1
                    qq_name_info = json.loads(user_info['bindings'][1]['tokenJsonStr']).get('nickname', '猪儿虫') if len(user_info['bindings'])>1 else '猪儿虫'
                    we_chat_info = json.loads(user_info['bindings'][2]['tokenJsonStr']).get('nickname', '猪儿虫') if len(user_info['bindings'])>2 else '猪儿虫'
                    current_user_info = login_info(background=background_url, user_header_img=user_header_img_url,
                                                   user_name=user_name_info, user_signature=user_sig_info, qq_name=qq_name_info,
                                                   we_chat_name=we_chat_info, csrf_token=self.token)
                else:
                    current_user_info = []
                return current_user_info
            else:
                return []
        except RequestException as e:
            raise Exception(e)

    def get_command_recource(self):
        """get music command recource"""
        song_sheet_element = ['sheet_from', 'sheet_id', 'sheet_name', 'sheet_img_url', 'play_count',
                              'create_user_name', 'song_info']
        song_sheet_info = collections.namedtuple('song_sheet_info', song_sheet_element)
        song_element = ['title', 'url']
        song_info = collections.namedtuple('song_info', song_element)
        if not self.token:
            return []
        else:
            result = []
            form_data = dict(csrf_token=self.token)
            data = self.login_cell_phone(form_data)
            response = requests.post(
                'https://music.163.com/weapi/discovery/recommend/resource?csrf_token={}'.format(self.token), data=data,
                headers=self.header, cookies=self.cookies)
            if response.status_code == 200:
                command_recource_json =json.loads(response.text).get('recommend', None)
                if command_recource_json:
                    for item in command_recource_json:
                        dic_info = {}
                        dic_info['sheet_from'] = item.get('copywriter', '')
                        dic_info['sheet_id'] = item.get('id')
                        dic_info['sheet_name'] = item.get('name')
                        dic_info['sheet_img_url'] = item.get('picUrl')
                        dic_info['play_count'] = item.get('playcount')
                        dic_info['create_user_name'] = item.get('creator', None).get('nickname') if item.get('creator', None) else ''
                        response_sheet = requests.get('https://music.163.com/playlist?id={}'.format(item.get('id')), cookies=self.cookies)
                        # if response_sheet.status_code == 200:
                        #     hrml_table = response_sheet.text
                        #     soup = BeautifulSoup(hrml_table, 'lxml')
                        #     chr = soup.select('ul.f-hide')[0].contents
                        dic_info['song_info'] = []
                        result.append(dic_info)
            return result

    def get_every_day_commend(self):
        """get everyday """
        song_info = collections.namedtuple('song_info', ['song_name', 'singer', 'art', 'reason'])
        if not self.token:
            return []
        else:
            result = []
            form_data = dict(csrf_token=self.token)
            data = self.login_cell_phone(form_data)
            response = requests.post(
                'https://music.163.com/weapi/v2/discovery/recommend/songs?csrf_token={}'.format(self.token), data=data,
                headers=self.header, cookies=self.cookies)
            if response.status_code == 200:
                songs_info = json.loads(response.text).get('recommend', None)
                if songs_info:
                    for item in songs_info:
                        dic_info = {}
                        dic_info['song_name'] = item.get('name', None)
                        dic_info['singer'] = item.get('artists')[0].get('name') if item.get('artists', None) else ''
                        dic_info['art'] = item.get('album', None).get('name', '') if item.get('album', None) else ''
                        dic_info['reason'] = item.get('reason', '')
                        result.append(song_info(**dic_info))
            return result


if __name__ == '__main__':
    avg_list = sys.argv
    user_phone, user_pass = (avg_list[1], avg_list[2])
    file_path = os.getcwd()
    if str(user_phone).isdigit():
        if all((user_phone, user_pass)):
            print('正在尝试模拟登陆....')
            music = NetEasyTopMusic(user_phone, user_pass)
            user_info = music.get_login_info()
            print('登陆成功，获取登陆信息')
            print('尝试抓取每日推荐歌单')
            everyday_recommend = music.get_every_day_commend()
            print('尝试获取个性推荐信息')
            recommend_info = music.get_command_recource()
            print('执行信息写入文件')
            with open(os.path.join(file_path, '{}.txt'.format(time.strftime("%Y-%m-%d", time.localtime()))), 'a') as f:
                f.write('当前用户信息：\n')
                f.write('背景地址:{}\n头像地址:{}\n昵称:{}\n说明:{}\nqq:{}\n微信:{}\n登陆凭证:{}'.format(user_info[0], user_info[1],
                                                user_info[2], user_info[3], user_info[4], user_info[5], user_info[6]))
                f.write('\n\n')
                f.write('{}日推荐歌单:\n'.format(time.strftime("%Y-%m-%d", time.localtime())))
                for song in everyday_recommend:
                    f.write('歌曲名:{},歌手:{},专辑:{},推荐原因:{} \n'.format(song.song_name, song.singer,
                                                                   song.art, song.reason))
                f.write('\n\n')
                f.write('今日推荐歌单信息：\n')
                for recommend in recommend_info:
                    f.write('推荐原因:{},歌单id:{},歌单名称:{},歌单背景:{},播放次数:{},创建者昵称:{} \n'.format(recommend.get('sheet_from'),
                            recommend.get('sheet_id'), recommend.get('sheet_name'), recommend.get('sheet_img_url'), recommend.get('play_count'),
                            recommend.get('create_user_name')))
                print('爬取完成')
    else:
        print('参数输入错误')



