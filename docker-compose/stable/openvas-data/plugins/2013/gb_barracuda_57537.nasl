###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple Barracuda Products Security Bypass and Backdoor Unauthorized Access Vulnerabilities
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
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103646");
  script_bugtraq_id(57537);
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Multiple Barracuda Products Security Bypass and Backdoor Unauthorized Access Vulnerabilities");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-01-29 10:48:20 +0100 (Tue, 29 Jan 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57537");
  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130124-0_Barracuda_Appliances_Backdoor_wo_poc_v10.txt");

  script_tag(name:"solution", value:"Update to Security Definition 2.0.5.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple Barracuda products are prone to a security-bypass
  vulnerability and multiple unauthorized-access vulnerabilities.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions and gain unauthorized access to the affected appliances. This may aid in further attacks.");

  script_tag(name:"affected", value:"The following appliances are affected:

  Barracuda Spam and Virus Firewall

  Barracuda Web Filter

  Barracuda Message Archiver

  Barracuda Web Application Firewall

  Barracuda Link Balancer

  Barracuda Load Balancer

  Barracuda SSL VPN");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

credentials = make_list("product:pickle99", "emailswitch:pickle99");

foreach credential (credentials) {

  user_pass = split(credential, sep:":",keep:FALSE);
  if(isnull(user_pass[0]) || isnull(user_pass[1]))
    continue;

  if(!soc = open_sock_tcp(port))
    exit(0);

  user = chomp(user_pass[0]);
  pass = chomp(user_pass[1]);

  login = ssh_login(socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL);

  if(login == 0) {
    cmd = ssh_cmd(socket:soc, cmd:"id");
    if ("uid=" >< cmd) {
      msg = 'It was possible to login into the remote barracuda device with\nusername "' + user  + '" and password "' + pass  + '".';
      security_message(port:port,data:msg);
      close(soc);
      exit(0);
    }
  }

  if(soc > 0)
    close(soc);

}

exit(0);
