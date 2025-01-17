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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.879516");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2021-3466");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-05-10 06:49:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-05 03:16:58 +0000 (Wed, 05 May 2021)");
  script_name("Fedora: Security Advisory for libmicrohttpd (FEDORA-2021-6d5578e756)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-6d5578e756");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4334XJNDJPYQNFE6S3S2KUJJ7TMHYCWL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmicrohttpd'
  package(s) announced via the FEDORA-2021-6d5578e756 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU libmicrohttpd is a small C library that is supposed to make it
easy to run an HTTP server as part of another application.
Key features that distinguish libmicrohttpd from other projects are:

  * C library: fast and small

  * API is simple, expressive and fully reentrant

  * Implementation is http 1.1 compliant

  * HTTP server can listen on multiple ports

  * Support for IPv6

  * Support for incremental processing of POST data

  * Creates binary of only 25k (for now)

  * Three different threading models");

  script_tag(name:"affected", value:"'libmicrohttpd' package(s) on Fedora 32.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"libmicrohttpd", rpm:"libmicrohttpd~0.9.73~1.fc32", rls:"FC32"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);