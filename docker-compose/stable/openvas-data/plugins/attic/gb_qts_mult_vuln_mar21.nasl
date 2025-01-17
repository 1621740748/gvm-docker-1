# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117291");
  script_version("2021-04-27T06:50:40+0000");
  script_tag(name:"last_modification", value:"2021-04-27 06:50:40 +0000 (Tue, 27 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 08:45:48 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-2509", "CVE-2020-9490");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.3.6.1620 Build 20210322 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'QNAP QTS Command Injection Vulnerability
  (QSA-21-05)' (OID: 1.3.6.1.4.1.25623.1.0.145776).

  QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-2509: command injection vulnerability

  - CVE-2020-9490: a vulnerability in Apache HTTP server");

  script_tag(name:"affected", value:"QNAP QTS prior to version 4.3.6.1620 Build 20210322.");

  script_tag(name:"solution", value:"Update to version 4.3.6.1620 Build 20210322 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/de-de/release-notes/qts/4.3.6.1620/20210322");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
