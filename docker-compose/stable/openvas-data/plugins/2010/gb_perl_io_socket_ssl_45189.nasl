# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:io-socket-ssl:io-socket-ssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100934");
  script_version("2021-07-14T12:36:58+0000");
  script_cve_id("CVE-2010-4334");
  script_bugtraq_id(45189);
  script_tag(name:"last_modification", value:"2021-07-14 12:36:58 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"creation_date", value:"2010-12-06 15:55:47 +0100 (Mon, 06 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("Perl IO::Socket::SSL 'verify_mode' Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_perl_modules_ssh_login_detect.nasl");
  script_mandatory_keys("perl/ssh-login/modules/io_socket_ssl/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45189");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=606058");
  script_xref(name:"URL", value:"http://cpansearch.perl.org/src/SULLR/IO-Socket-SSL-1.35/Changes");
  script_xref(name:"URL", value:"http://search.cpan.org/dist/IO-Socket-SSL/");

  script_tag(name:"summary", value:"The IO::Socket::SSL module for Perl is prone to a security-
  bypass vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to bypass
  certain security restrictions, which may aid in spoofing attacks.");

  script_tag(name:"affected", value:"Versions prior to 1.35 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.35" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.35", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );