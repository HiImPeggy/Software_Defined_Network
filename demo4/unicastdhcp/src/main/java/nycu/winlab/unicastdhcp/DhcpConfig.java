/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.unicastdhcp;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;

public class DhcpConfig extends Config<ApplicationId> {

  public static final String SERVER_LOCATION = "serverLocation";
  public static final String H2_LOCATION = "h2Location";

  @Override
  public boolean isValid() {
    return hasOnlyFields(SERVER_LOCATION);
  }

  public String serverLocation() {
    return get(SERVER_LOCATION, null);
  }

  public String h2Location() {
        return get(H2_LOCATION, null);
  }
}

