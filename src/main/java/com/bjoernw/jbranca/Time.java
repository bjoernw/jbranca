/**
 *
 *  Copyright © 2018 Bjoern Weidlich <bjoernweidlich@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.bjoernw.jbranca;

class Time {

    private Time() {
    }

    static int unixTimeNow() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static byte[] bigEndian(int unixTime) {
        return new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime
        };
    }

    static byte[] makeTimestamp() {
        return bigEndian(unixTimeNow());
    }
}
