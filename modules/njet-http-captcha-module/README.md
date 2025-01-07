## Module:

### Example Configuration:
```nginx
location =/captcha {
    captcha;
}
location =/login {
    set_form_input $csrf_form csrf;
    set_unescape_uri $csrf_unescape $csrf_form;
    set_form_input $captcha_form captcha;
    set_unescape_uri $captcha_unescape $captcha_form;
    set_md5 $captcha_md5 "secret${captcha_unescape}${csrf_unescape}";
    if ($captcha_md5 != $cookie_captcha) {
        # captcha invalid code
    }
}
```
### Directives:

    Syntax:	 captcha;
    Default: ——
    Context: location

Enables generation of captcha image.<hr>

    Syntax:	 captcha_case on | off;
    Default: off
    Context: http, server, location

Enables/disables ignoring captcha case.<hr>

    Syntax:	 captcha_expire seconds;
    Default: 3600
    Context: http, server, location

Sets seconds before expiring captcha.<hr>

    Syntax:	 captcha_height pixels;
    Default: 30
    Context: http, server, location

Sets height of captcha image.<hr>

    Syntax:	 captcha_length characters;
    Default: 4
    Context: http, server, location

Sets length of captcha text.<hr>

    Syntax:	 captcha_size pixels;
    Default: 20
    Context: http, server, location

Sets size of captcha font.<hr>

    Syntax:	 captcha_width pixels;
    Default: 130
    Context: http, server, location

Sets width of captcha image.<hr>

    Syntax:	 captcha_charset string;
    Default: abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789
    Context: http, server, location

Sets characters used in captcha text.<hr>

    Syntax:	 captcha_csrf string;
    Default: csrf
    Context: http, server, location

Sets name of csrf var of captcha.<hr>

    Syntax:	 captcha_font string;
    Default: /usr/share/fonts/ttf-liberation/LiberationSans-Regular.ttf
    Context: http, server, location

Sets font of captcha text.<hr>

    Syntax:	 captcha_name string;
    Default: Captcha
    Context: http, server, location

Sets name of captcha cookie.<hr>

    Syntax:	 captcha_secret string;
    Default: secret
    Context: http, server, location

Sets secret of captcha.
