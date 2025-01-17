###############################################################################
#
# FingerTec Devices Telnet Default Credentials Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807525");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-03-16 15:57:40 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("FingerTec Devices Telnet Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is installed with FingerTec
  device and is prone to default credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Check if it is possible to do telnet
  login into the FingerTec device.");

  script_tag(name:"insight", value:"The flaw is due to default user:passwords
  which is publicly known and documented.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain unauthorized root access to affected devices and completely
  compromise the devices.");

  script_tag(name:"affected", value:"FingerTec Devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/fingertex/device/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

fingport = telnet_get_port(default:23);
if(!banner = telnet_get_banner(port:fingport)) exit(0);
if("ZEM" >!< banner) exit(0);

soc = open_sock_tcp(fingport);
if(!soc) exit(0);

creds = make_array("root", "founder88",
                   "root", "colorkey",
                   "root", "solokey",
                   "root","swsbzkgn",
                   "admin", "admin",
                   "888", "manage",
                   "manage", "888",
                   "asp", "test",
                   "888", "asp",
                   "root", "root",
                   "admin","1234");

foreach cred ( keys( creds ) )
{
  recv = recv( socket:soc, length:2048 );
  if ("login:" >< recv)
  {
    send(socket:soc, data: cred + '\r\n');
    recv = recv(socket:soc, length:128);
    if("Password:" >< recv)
    {
      send(socket:soc, data: creds[cred] + '\r\n');
      recv = recv(socket:soc, length:1024);

      if(recv =~ "BusyBox v([0-9.]+)")
      {
        report += "\n\n" + cred + ":" + creds[cred] + "\n";
        security_message(port:fingport, data:report);
        close(soc);
      }
    }
  }
}

close(soc);
