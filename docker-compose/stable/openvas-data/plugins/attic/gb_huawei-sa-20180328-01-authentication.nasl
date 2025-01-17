###############################################################################
# OpenVAS Vulnerability Test
#
# Huawei Switches Improper Authorization Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112259");
  script_version("2020-07-29T06:10:44+0000");
  script_tag(name:"last_modification", value:"2020-07-29 06:10:44 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2018-04-24 11:11:11 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15327");

  script_name("Huawei Switches Improper Authorization Vulnerability (huawei-sa-20180328-01-authentication)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is an improper authorization vulnerability on Huawei switch products.
  The system incorrectly performs an authorization check when a normal user attempts to access certain information
  which is supposed to be accessed only by authenticated user.

  This NVT has been deprecated as SA is already covered by following VT:

  - 'Huawei Data Communication: Improper Authorization Vulnerability on Huawei Switch Products (huawei-sa-20180328-01-authentication)' (OID:1.3.6.1.4.1.25623.1.0.107825)");

  script_tag(name:"vuldetect", value:"The script checks if the target host is an affected product that has a vulnerable
  firmware version installed.");

  script_tag(name:"impact", value:"Successful exploit could cause information disclosure.");

  script_tag(name:"affected", value:"The following Huawei Switch models and firmware versions are affected:

  Huawei Switch S12700 versions: V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R007C20, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S7700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S9700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R009C00, V200R010C00");

  script_tag(name:"solution", value:"Update the software according to your product:

  Huawei Campus Switch S12700/S7700/S9700 fixed version: V200R010SPH002");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180328-01-authentication-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
