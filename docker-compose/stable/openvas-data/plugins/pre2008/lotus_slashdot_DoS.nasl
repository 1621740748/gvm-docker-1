# OpenVAS Vulnerability Test
# Description: Lotus /./ database lock
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
#

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11718");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_bugtraq_id(3656);
  script_cve_id("CVE-2001-0954");

  script_name("Lotus /./ database lock");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"solution", value:"Upgrade your Lotus Domino server.");

  script_tag(name:"summary", value:"It might be possible to lock out some Lotus Domino databases by
  requesting them through the web interface with a special request like /./name.nsf
  This attack is only efficient on databases that are not used by the server.");

  script_tag(name:"vuldetect", value:"Note that no real attack was performed, so this might be a false alert.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE  ))
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"5.0.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.9" );
  security_message( data:report, port:0 );
  exit(0);
}

exit( 99 );
