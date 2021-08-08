# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:vcenter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140254");
  script_cve_id("CVE-2017-5641");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2021-03-29T14:39:17+0000");
  script_name("VMware vCenter Server Remote Code Execution Vulnerability (VMSA-2017-0007)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0007.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the
  target host.");

  script_tag(name:"insight", value:"VMware vCenter Server contains a remote code execution
  vulnerability due to the use of BlazeDS to process AMF3 messages. This issue may be
  exploited to execute arbitrary code when deserializing an untrusted Java object.");

  script_tag(name:"solution", value:"See vendor advisory for a solution.");

  script_tag(name:"summary", value:"Remote code execution vulnerability via BlazeDS.");

  script_tag(name:"affected", value:"vCenter 6.5 and 6.0.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-03-29 14:39:17 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-04-18 11:03:22 +0200 (Tue, 18 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/detected", "vmware/vcenter/build");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/build" ) )
  exit( 0 );

if( version == "6.0.0" )
  if( int( build ) <= int( 5318198 ) )
    fix = "6.0 3b";

if( version == "6.5.0" )
  if( int( build ) < int( 5318112 ) )
    fix = "6.5.0c";

if( fix ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fix, typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );
