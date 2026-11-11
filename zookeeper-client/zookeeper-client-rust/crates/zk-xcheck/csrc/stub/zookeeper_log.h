/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Stand-in for include/zookeeper_log.h. The log macros record each line in
 * a buffer, so that the tests can compare the C log output. Debug lines are
 * dropped, and their arguments are not evaluated.
 */
#ifndef ZK_LOG_H_
#define ZK_LOG_H_

void zkx_log(const char *level, const char *fmt, ...);

#define LOGCALLBACK(_zh) ((void *)0)
#define LOG_ERROR(_cb, ...) zkx_log("ERROR", __VA_ARGS__)
#define LOG_WARN(_cb, ...) zkx_log("WARN", __VA_ARGS__)
#define LOG_INFO(_cb, ...) zkx_log("INFO", __VA_ARGS__)
#define LOG_DEBUG(_cb, ...) ((void)0)

#endif
