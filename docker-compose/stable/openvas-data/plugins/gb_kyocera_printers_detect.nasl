###############################################################################
# OpenVAS Vulnerability Test
#
# Kyocera Printer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103707");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-05-08 11:31:24 +0100 (Wed, 08 May 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kyocera Printer Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Kyocera Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Kyocera printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("kyocera_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

urls = get_ky_detect_urls();

foreach url(keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string:url, pattern:"(#--avoid-dup[0-9]+--#)", replace:"");

  buf = http_get_cache(item:url, port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  if(kyo = eregmatch(pattern:pattern, string:buf, icase:TRUE)) {

    if(!isnull(kyo[1])) {

      concluded = kyo[0];
      model     = kyo[1];

      set_kb_item(name:"kyocera_printer/installed", value:TRUE);
      set_kb_item(name:"kyocera_printer/port", value:port);
      set_kb_item(name:"kyocera_model", value:model);

      cpe_model = tolower(model);

      cpe = "cpe:/h:kyocera:" + cpe_model;
      cpe = str_replace(string:cpe, find:" ", replace:"_");

      register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");
      log_message(port:port, data:"The remote Host is a Kyocera " + model + " printer device.\nCPE: " + cpe + "\nConcluded: " + concluded);

      pref = get_kb_item("global_settings/exclude_printers");
      if(pref == "yes") {
        log_message(port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
        set_kb_item(name:"Host/dead", value:TRUE);
      }
      exit(0);
    }
  }
}

exit(0);
