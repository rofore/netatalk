if have_atfuncs and have_bdb
    subdir('ad')
endif
subdir('adv1tov2')
if have_ssl
    subdir('afppasswd')
endif
subdir('cnid')
subdir('megatron')
subdir('uniconv')
subdir('misc')

if not get_option('enable-ddp').disabled()
    subdir('aecho')
    subdir('getzones')
    subdir('nbp')
    subdir('pap')
    subdir('psorder')
endif
