#!/usr/bin/env python
from asyncio.subprocess import PIPE
import time
import datetime
import subprocess
from pprint import pprint
#zapライブラリは別途設置
from zapv2 import ZAPv2
import os
import sys
import urllib

program_file_path = os.environ["ProgramFiles"]
owasp_zap_bat_path = "\OWASP\Zed Attack Proxy\zap.bat"
owasp_zap_path = "\OWASP\Zed Attack Proxy"

full_zap_path = program_file_path + owasp_zap_path
full_bat_path = program_file_path + owasp_zap_bat_path

#追加オプション
daemon_mode = "-daemon"
new_session_flg = "-newsession"
opt_session = "-session"

bat_cmd = os.path.abspath(full_bat_path)

ar_bat_cmd = [bat_cmd, daemon_mode, new_session_flg, opt_session]

os.chdir(os.path.abspath(full_zap_path))
arg = [daemon_mode, new_session_flg]

path = "D:\\Users\\your-user\\Desktop\\test.py"
buf = []
init_flg = True

if init_flg:
    target = "https://xxxx.xxxx.co.jp"

    #api接続オプション
    api_key = "your-api-key"
    local_proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

    #毎回新しいセッションにする
    new_session_flg = True
    #診断日付日時を変更する
    session_name = "test_session"

    #必要か要確認
    global_exclude_url = ['^(?:(?!http:\/\/localhost:8081).*).$']

    proxychain_flg = False
    proxy_script_flg = False

    use_context_for_scan_flg = True
    define_new_context_flg = True
    context_name = "automated_scan_context"
    context_id = 0

    context_include_url = [target + ".*"]
    context_exclude_url = []

    session_management = "cookieBasedSessionManagement"
    auth_method = "formBasedAuthentication"

    #フォームベース認証
    login_url = "https://xxxx.xxxx.co.jp/your-login-page"
    login_request_data = 'loginid={%username%}&loginpass={%password%}'
    form_based_login_auth_params = "loginUrl=" + urllib.parse.quote(login_url) + "&loginRequestData=" + urllib.parse.quote(login_request_data)

    is_logged_in_indicator = True
    #要確認
    indicator_regex = ""

    create_user_flg = True
    test_user1_name = "scan_user"
    test_user1_loginid = "pentestuser1"
    test_user1_loginpw = "Abcd12345Abcd"
    ar_user = [
        {"name": "scan_user", "credentials" : "username=" + urllib.parse.quote(test_user1_loginid) + "&password=" + urllib.parse.quote(test_user1_loginpw)}
    ]

    user_id_list = []

    use_scan_policy = True
    scan_policy_name = "custom_policy"
    is_whit_list_policy = False
    alert_threshold = "Low"
    attack_strength = "Insane"

    use_ajax_spider_flg = False
    shut_down_once_finished = False

    client_certificate_pk12_path = "D:\\Users\\your-user\\Documents\\client_cert.pfx"
    client_certificate_pk12_password = "xxxxxxxx"

    #####################
    ####コンフィグ完了####
    #####################

    zap = ZAPv2(apikey=api_key, proxies=local_proxies)

    #ZAP セッションを立ち上げる
    core = zap.core
    core.enable_pkcs_12_client_certificate(client_certificate_pk12_path, client_certificate_pk12_password, apikey=api_key)
    action_mode = "protect"
    core.set_mode(mode=action_mode)
    if new_session_flg:
        pprint('Create ZAP session: ' + session_name + ' -> ' + core.new_session(name=session_name, overwrite=True))
    else:
        pprint('Load ZAP session: ' + session_name + ' -> ' + core.load_session(name=session_name))

    #Context設定
    for regex in global_exclude_url:
        pprint(regex + ' ->' + core.exclude_from_proxy(regex=regex))

    if use_context_for_scan_flg:
        #context設定
        context = zap.context
        if define_new_context_flg:
            context_id = context.new_context(contextname=context_name)
        pprint('Use context ID: ' + context_id)

        #include url追加
        print('Include URL in context:')
        for url in context_include_url:
            pprint(url + ' -> ' + context.include_in_context(contextname=context_name, regex=url))
        
        pprint('Set session management method: ' + session_management + ' -> ' +
            zap.sessionManagement.set_session_management_method(
                contextid=context_id, methodname=session_management,
                methodconfigparams=None))
        
        #認証方法を設定する
        auth = zap.authentication
        pprint('Set authentication method: ' + auth_method + ' -> ' + auth.set_authentication_method(contextid=context_id, authmethodname=auth_method, authmethodconfigparams=form_based_login_auth_params))

        users = zap.users
        if create_user_flg:
            for user in ar_user:
                userName = user.get('name')
                print('Create user ' + userName + ':')
                userId = users.new_user(contextid=context_id, name=userName)
                user_id_list.append(userId)
                pprint('User ID: ' + userId + '; username -> ' +
                        users.set_user_name(contextid=context_id, userid=userId,
                                            name=userName) +
                        '; credentials -> ' +
                        users.set_authentication_credentials(contextid=context_id,
                            userid=userId,
                            authcredentialsconfigparams=user.get('credentials')) +
                        '; enabled -> ' +
                        users.set_user_enabled(contextid=context_id, userid=userId,
                                            enabled=True))
    
    #静的スキャン
    pprint('Enable all passive scanners -> ' +
    zap.pscan.enable_all_scanners())

    active_scan = zap.ascan

    if use_scan_policy:
        active_scan.remove_scan_policy(scanpolicyname=scan_policy_name)
        pprint('Add scan policy ' + scan_policy_name + ' -> ' + active_scan.add_scan_policy(scanpolicyname=scan_policy_name))

        for policy_id in range (0, 5):
            active_scan.set_policy_alert_threshold(id=policy_id, alertthreshold=alert_threshold, scanpolicyname=scan_policy_name)
            active_scan.set_policy_attack_strength(id=policy_id, attackstrength=attack_strength, scanpolicyname=scan_policy_name)

    else:
        print("No custom policy used for scan")
        scan_policy_name = None

    pprint('Accessing target:{}'.format(target))

    force_user = zap.forcedUser
    spider = zap.spider
    ajax_spider = zap.ajaxSpider
    scan_id = 0


    core.access_url(url=target, followredirects=True)
    time.sleep(2)

    for userId in user_id_list:
        print('Starting scans with User ID: ' + userId)

        #スパイダーを設定
        scan_id = spider.scan_as_user(contextid=context_id, userid=userId,
                url=target, maxchildren=None, recurse=True, subtreeonly=None)
        print('Start Spider scan with user ID: ' + userId +
                '. Scan ID equals: ' + scan_id)
        #スパイダーを起動する
        time.sleep(2)
        while (int(spider.status(scan_id)) < 100):
            print('Spider progress: ' + spider.status(scan_id) + '%')
            time.sleep(2)
        print('Spider scan for user ID ' + userId + ' completed')
        print("\n".join(map(str, zap.spider.results(scan_id))))

        #デバッグ用にタイムアウトを設ける
        timeout = time.time() + 60*2
        pprint('Set forced user mode enabled -> ' +
                force_user.set_forced_user_mode_enabled(boolean=True))
        pprint('Set user ID: ' + userId + ' for forced user mode -> ' +
                    force_user.set_forced_user(contextid=context_id,
                        userid=userId))
        #Ajaxスパイダーを起動する
        pprint('Ajax Spider the target with user ID: ' + userId + ' -> ' +
                    ajax_spider.scan(url=target, inscope=None))
        time.sleep(10)
        #ajax spiderは時間かかるので、いったんコメントアウト
        while (ajax_spider.status != 'stopped'):
            if time.time() > timeout:
                break
            print('Ajax Spider is ' + ajax_spider.status)
            time.sleep(5)
        pprint('Set forced user mode disabled -> ' +
                force_user.set_forced_user_mode_enabled(boolean=False))
        print('Ajax Spider scan for user ID ' + userId + ' completed')

        #-------------
        #デバッグで少しプリントする
        #print(ajax_spider.results(scan_id, count=10))
        #print(scan_id)
        #-------------

        #動的スキャン
        scan_id = active_scan.scan_as_user(contextid=context_id, userid=userId,
                url=target, recurse=True, scanpolicyname=scan_policy_name, method=None, postdata=True)
        
        print('Start Active Scan with user ID: ' + userId +
                '. Scan ID equals: ' + scan_id)
        time.sleep(2)
        while (int(active_scan.status(scan_id)) < 100):
            print('Active Scan progress: ' + active_scan.status(scan_id) + '%')
            time.sleep(2)
        print('Active Scan for user ID ' + userId + ' completed')

    time.sleep(5)
    print('HTML report:')

    now_time = datetime.datetime.now()
    with open("c:\\Users\\your-user\\Desktop\\output{}.html".format(now_time.strftime('%Y%m%d_%H%M%S')), mode='w') as f:
        f.write(core.htmlreport())