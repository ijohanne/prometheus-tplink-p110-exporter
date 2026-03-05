self:
{ config, lib, pkgs, ... }:
with lib;
let
  cfg = config.services.prometheus-tplink-p110-exporter;
  name = "tplink-p110";
  package = self.packages.${pkgs.system}.default;
in
{
  options.services.prometheus-tplink-p110-exporter = with types; mkOption {
    type = types.submodule {
      options = {
        enable = mkEnableOption "the prometheus ${name} exporter";
        enableLocalScraping = mkEnableOption "enable scraping by local prometheus";
        port = mkOption {
          type = types.port;
          default = 9981;
          description = ''
            Port to listen on.
          '';
        };
        listenAddress = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = ''
            Address to listen on.
          '';
        };
        username = mkOption {
          type = types.nullOr types.str;
          description = ''
            TP-Link username to use (usually email address)
          '';
        };
        password = mkOption {
          type = types.nullOr types.str;
          description = ''
            TP-Link password to use
          '';
        };
        hosts = mkOption {
          type = types.listOf types.str;
          description = ''
            Hosts to monitor
          '';
        };
        user = mkOption {
          type = types.str;
          default = "${name}-exporter";
          description = ''
            User name under which the ${name} exporter shall be run.
          '';
        };
        group = mkOption {
          type = types.str;
          default = "${name}-exporter";
          description = ''
            Group under which the ${name} exporter shall be run.
          '';
        };
      };
    };
    default = { };
  };
  config = mkIf cfg.enable {
    users.users."${cfg.user}" = {
      description = "Prometheus ${name} exporter service user";
      isSystemUser = true;
      group = "${cfg.group}";
    };
    users.groups."${cfg.group}" = { };

    systemd.services."prometheus-${name}-exporter" =
      let
        hosts = concatStringsSep " " (forEach cfg.hosts (host: ''--host ${host}''));
      in
      {
        environment = { };
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.Restart = "always";
        serviceConfig.PrivateTmp = true;
        serviceConfig.WorkingDirectory = /tmp;
        serviceConfig.DynamicUser = false;
        serviceConfig.User = "${cfg.user}";
        serviceConfig.Group = "${cfg.group}";
        serviceConfig.ExecStart = ''
          ${getBin package}/bin/prometheus-tplink-p110-exporter \
          --listen-address ${cfg.listenAddress} \
          --listen-port ${toString cfg.port} \
          --username ${cfg.username} \
          --password ${cfg.password} \
          ${hosts}
        '';
      };

    services.prometheus.scrapeConfigs = mkIf cfg.enableLocalScraping [
      {
        job_name = "${name}";
        honor_labels = true;
        static_configs = [{
          targets = [ "127.0.0.1:${toString cfg.port}" ];
        }];
      }
    ];
  };
}
