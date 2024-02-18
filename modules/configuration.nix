{
  lib,
  pkgs,
  ...
}: let
  username = "chenjf";
  # To generate a hashed password run `mkpasswd`.
  # this is the hash of the password "rk3588"
  hashedPassword = "$y$j9T$U.t7m6E8cELNNcY4yatIx1$XfaRrx7xZch1tfnZo16oCboW1wtp7ujnTLe70nSwCA.";
  # TODO replace this with your own public key!
  publickey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDouazcY0grLX8lAz/XrtDS1ZIo0s91BS7VrCKlzfRZtmcoI041vz+SBCCWbtnOMmWRFtA948aGtCN6EKD3JSREmrmJU1JfTIoekYzemdbjMbsTnIw0czP7weFtfFgdwhn8vro11k3uy0uG/32+aUYNUx+CNaDKulBRtg+oXRmjkrHCtapCHpN9/FMsvZjP0NbqVKtbf5Jem6Pqx8Himo3cZq3SKSYG8UIC/mAebEz793M5rR4FSvzXlfgiwCBn07F3+0rQAL6ZtsNEE521iJyU88tk6VsewPsZNvguCY21y3eKGYsny+ITMfR4liZjToIkrJGt3l7EMJawsAUemMWz hugh.jf.chen@gmail.com";
in {
  nix.settings = {
    experimental-features = ["nix-command" "flakes"];
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    git # used by nix flakes
    curl

    neofetch
    lm_sensors # `sensors`
    btop # monitor system resources

    # Peripherals
    mtdutils
    i2c-tools
    minicom
  ];

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ 22 80 443 ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;
  # Enable the OpenSSH daemon.

  services.openssh = {
    enable = lib.mkDefault true;
    settings = {
      X11Forwarding = lib.mkDefault true;
      PasswordAuthentication = lib.mkDefault true;
    };
    openFirewall = lib.mkDefault true;
  };

  # =========================================================================
  #      Users & Groups NixOS Configuration
  # =========================================================================

  # TODO Define a user account. Don't forget to update this!
  users.users."${username}" = {
    inherit hashedPassword;
    isNormalUser = true;
    home = "/home/${username}";
    extraGroups = ["users" "networkmanager" "wheel" "video" "docker"];
    openssh.authorizedKeys.keys = [
      publickey
    ];
  };

  users.users.root.openssh.authorizedKeys.keys = [
    publickey
  ];

  users.groups = {
    "${username}" = {};
    docker = {};
  };

  # config NOPASSWORD for the user
  security.sudo.extraRules= [
    { users = [ "${username}" ];
      commands = [
        { command = "ALL" ;
           options= [ "NOPASSWD" ]; # "SETENV" # Adding the following could be a good idea
        }
      ];
    }
  ];

  # some env settting for shell
  environment.interactiveShellInit = ''
    alias 'ltr=ls -ltr'
    export 'TERM=xterm-color'
  '';

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.05"; # Did you read the comment?
}
