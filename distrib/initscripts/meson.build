if get_option('enable-redhat-sysv')
    init_dir += '/etc/rc.d/init.d'
    custom_target(
        'redhat_sysv',
        input: 'rc.atalk.redhat-sysv.tmpl',
        output: 'netatalk',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
        install_mode: 'rwxr-xr-x',
    )
    meson.add_install_script(
        find_program('chkconfig'),
        'add',
        '/etc/rc.d/init.d/netatalk',
    )
elif get_option('enable-systemd')
    init_dir += '/usr/lib/systemd/system'
    service_data = [
        'a2boot',
        'afpd',
        'atalkd',
        'cnid',
        'papd',
        'timelord',
    ]
    foreach service : service_data
        custom_target(
            service + '.service',
            input: service + '.service.tmpl',
            output: service + '.service',
            command: sed_command,
            capture: true,
            install: true,
            install_dir: prefix / init_dir,
        )
    endforeach
    meson.add_install_script(find_program('systemctl'), 'daemon-reload')
elif get_option('enable-suse-sysv')
    init_dir += '/etc/init.d'
    custom_target(
        'suse_sysv',
        input: 'rc.atalk.suse-sysv.tmpl',
        output: 'netatalk',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
        install_mode: 'rwxr-xr-x',
    )
    meson.add_install_script(find_program('insserv'), '/etc/init.d/netatalk')
elif get_option('enable-netbsd')
    init_dir += '/etc/rc.d'
    rc_scripts = [
        'rc.afpd',
        'rc.atalkd',
        'rc.cnid_metad',
        'rc.papd',
        'rc.timelord',
        'rc.a2boot',
    ]
    foreach script : rc_scripts
        custom_target(
            script + '.netbsd',
            input: script + '.netbsd.tmpl',
            output: script + 'netbsd',
            command: sed_command,
            capture: true,
            install: true,
            install_dir: init_dir,
            install_mode: 'rwxr-xr-x',
        )
    endforeach
elif get_option('enable-solaris')
    init_dir += '/etc/init.d'
    custom_target(
        'solaris',
        input: 'rc.atalk.sysv.tmpl',
        output: 'netatalk',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
    )
    meson.add_install_script(
        find_program('rm'),
        '-f',
        '/etc/rc2.d/S90netatalk',
    )
    meson.add_install_script(
        find_program('ln'),
        '-s',
        '/etc/init.d/netatalk',
        '/etc/rc2.d/S90netatalk',
    )
    meson.add_install_script(
        find_program('ln'),
        '-s',
        '/etc/init.d/netatalk',
        '/etc/rc0.d/K04netatalk',
    )
elif get_option('enable-gentoo')
    init_dir += '/etc/init.d'
    custom_target(
        'gentoo',
        input: 'rc.atalk.gentoo.tmpl',
        output: 'netatalk',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
        install_mode: 'rwxr-xr-x',
    )
elif get_option('enable-debian')
    init_dir += '/etc/init.d'
    custom_target(
        'debian_sysv',
        input: 'rc.atalk.debian.tmpl',
        output: 'netatalk',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
        install_mode: 'rwxr-xr-x',
    )
elif get_option('enable-macos')
    init_dir += '/Library/LaunchDaemons'
    custom_target(
        'netatalkd',
        input: 'netatalkd.tmpl',
        output: 'netatalkd',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: bindir,
        install_mode: 'rwxr-xr-x',
    )
    custom_target(
        'plist',
        input: 'com.netatalk.daemon.plist.tmpl',
        output: 'com.netatalk.daemon.plist',
        command: sed_command,
        capture: true,
        install: true,
        install_dir: init_dir,
    )
    if not fs.exists(init_dir / 'com.netatalk.daemon.plist')
        meson.add_install_script(
            find_program('launchctl'),
            'load',
            '-w',
            init_dir / 'com.netatalk.daemon.plist',
        )
    endif
endif

