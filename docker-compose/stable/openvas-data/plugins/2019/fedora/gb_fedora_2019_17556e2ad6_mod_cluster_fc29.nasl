# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.876351");
  script_version("2019-05-14T05:04:40+0000");
  script_cve_id("CVE-2016-8612", "CVE-2016-3110");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-14 05:04:40 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-11 02:12:28 +0000 (Sat, 11 May 2019)");
  script_name("Fedora Update for mod_cluster FEDORA-2019-17556e2ad6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-17556e2ad6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HE5YZTBZRXCMQFT5LDLZG2HAYBKMYQLL");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'mod_cluster' package(s) announced via the FEDORA-2019-17556e2ad6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"Mod_cluster is an httpd-based load balancer.
  Like mod_jk and mod_proxy, mod_cluster uses a communication channel to forward
  requests from httpd to one of a set of application server nodes. Unlike mod_jk
  and mod_proxy, mod_cluster leverages an additional connection between the
  application server nodes and httpd. The application server nodes use this
  connection to transmit server-side load balance factors and lifecycle events
  back to httpd via a custom set of HTTP methods, affectionately called the
  Mod-Cluster Management Protocol (MCMP). This additional feedback channel
  allows mod_cluster to offer a level of intelligence and granularity not
  found in other load balancing solutions.");

  script_tag(name:"affected", value:"'mod_cluster' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"mod_cluster", rpm:"mod_cluster~1.3.11~1.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
