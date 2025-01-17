##############################################################################
# OpenVAS Vulnerability Test
#
# EasyPHP Webserver Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803189");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-04-09 11:29:34 +0530 (Tue, 09 Apr 2013)");
  script_name("EasyPHP Webserver Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/easyphp-webserver-php-command-execution");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The bug in EasyPHP WebServer Manager, its skipping
  authentication for certain requests. Which allows to bypass the authentication,
  disclose the information or execute a remote PHP code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running EasyPHP Webserver and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain
  administrative access, disclose the information, inject PHP code/shell and
  execute a remote PHP Code.");

  script_tag(name:"affected", value:"EasyPHP version 12.1 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

#[EasyPHP] - Administration<
if(http_vuln_check(port:port, url:"/phpinfo.php",
   pattern:"\[EasyPHP\]", check_header:TRUE, usecache:TRUE,
   extra_check:make_list(">Configuration<", ">PHP Core<", "php.ini")))
{
  security_message(port:port);
  exit(0);
}
