###############################################################################
# OpenVAS Vulnerability Test
#
# FtpLocate fsite Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.803847");
  script_version("2020-08-24T15:18:35+0000");
  script_bugtraq_id(60760);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-08-01 10:40:30 +0530 (Thu, 01 Aug 2013)");
  script_name("FtpLocate fsite Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running FtpLocate and is prone to cross-site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  read the cookie or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Input passed via 'fsite' parameter to 'flsearch.pl' script is not properly
  sanitised before being returned to the user.");

  script_tag(name:"affected", value:"FtpLocate version 2.02, other versions may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.1337day.com/exploit/20938");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/85250");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122144");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/ftplocate-202-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/ftplocate", "/ftp", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir,"/flsummary.pl"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if('>FtpLocate' >< res && 'Ftp Search Engine<' >< res)
  {
    url = dir + '/flsearch.pl?query=FTP&amp;fsite=<script>' +
                'alert(document.cookie)</script>';

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\)</script>"))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
