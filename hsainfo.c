/* hsainfo: a small program to list HSA devices & their properties.

   Copyright (c) 2016 Michal Babej

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/


#include <stdlib.h>
#include <stdio.h>

#include "hsa.h"
#include "hsa_ext_finalize.h"
#include "hsa_ext_image.h"
#include "hsa_ext_amd.h"

static void
abort_on_hsa_error(hsa_status_t status,
                            unsigned line,
                            const char* func,
                            const char* code)
{
  const char* str;
  if (status != HSA_STATUS_SUCCESS)
    {
      hsa_status_string(status, &str);
      printf("HSA ERROR in %s() @ %u: %s\n", func, line, str);
      abort();
    }
}

#define HSA_CHECK(code) abort_on_hsa_error(code,         \
                                           __LINE__,     \
                                           __FUNCTION__, \
                                           #code);



#define MAX_HSA_AGENTS 16
static hsa_agent_t hsa_agents[MAX_HSA_AGENTS];
static unsigned found_hsa_agents = 0;

static hsa_status_t
hsa_get_agents_callback(hsa_agent_t agent, void *data)
{
  hsa_agent_feature_t features;
  HSA_CHECK(hsa_agent_get_info(agent, HSA_AGENT_INFO_FEATURE, &features));
  if (features == HSA_AGENT_FEATURE_KERNEL_DISPATCH)
  hsa_agents[found_hsa_agents++] = agent;
  return HSA_STATUS_SUCCESS;
}



#define GET_AGENT_INFO(INFO, MSG, TYPE, FORMATTER) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AGENT_INFO_ ## INFO, &x)); \
  printf("    %-22s  " FORMATTER "\n", MSG, x); \
} while (0)

#define GET_AGENT_INFO_STR(INFO, MSG, TYPE, FORMATTER) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AGENT_INFO_ ## INFO, x)); \
  printf("    %-22s  " FORMATTER "\n", MSG, x); \
} while (0)

#define GET_AGENT_INFO_ENUM(INFO, MSG, TYPE, PRINT_FUNC) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AGENT_INFO_ ## INFO, &x)); \
  const char *r; \
  PRINT_FUNC(x, &r); \
  printf("    %-22s  %s\n", MSG, r); \
} while (0)

#define GET_AGENT_INFO_ARRAY(INFO, TYPE, PRINT_FUNC) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AGENT_INFO_ ## INFO, x)); \
  PRINT_FUNC(x); \
} while (0)

#define GET_AGENT_INFO_STRUCT(INFO, TYPE, PRINT_FUNC) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AGENT_INFO_ ## INFO, &x)); \
  PRINT_FUNC(x); \
} while (0)

// ####################################################################

#define AMD_GET_AGENT_INFO(INFO, MSG, TYPE, FORMATTER) \
do { \
  TYPE x; \
  HSA_CHECK(hsa_agent_get_info (agent, HSA_AMD_AGENT_INFO_ ## INFO, &x)); \
  printf("    %-22s  " FORMATTER "\n", MSG, x); \
} while (0)



// ####################################################################

typedef char name_t[128];
typedef uint16_t wg_dim3_t[3];
typedef uint32_t cache_size_t[4];

void print_type(hsa_device_type_t t, const char **r)
{
  *r = ((t == HSA_DEVICE_TYPE_CPU ) ? "CPU" : (t == HSA_DEVICE_TYPE_GPU ? "GPU" : "DSP"));
}

void print_role(hsa_agent_feature_t t, const char **r)
{
  *r = (t == HSA_AGENT_FEATURE_KERNEL_DISPATCH ? "Kernel dispatch" : "Agent dispatch");
}

void print_model(hsa_machine_model_t t, const char **r)
{
  *r = (t == HSA_MACHINE_MODEL_SMALL ? "Small(32bit)" : "Large(64bit)");
}

void print_profile(hsa_profile_t t, const char **r)
{
  *r = (t == HSA_PROFILE_BASE ? "Base" : "Full");
}

void print_queue_type(hsa_queue_type_t t, const char **r)
{
  *r = (t == HSA_QUEUE_TYPE_MULTI ? "Multi" : "Single");
}

void print_cache_sizes(cache_size_t t)
{
  printf("    Cache sizes [L1..L4]:   %u %u %u %u\n", t[0], t[1], t[2], t[3]);
}

void print_grid_sizes(hsa_dim3_t t)
{
  printf("    Grid max sizes:         %u %u %u\n", t.x, t.y, t.z);
}

void print_wg_sizes(wg_dim3_t t)
{
  printf("    WG max sizes:           %hu %hu %hu\n", t[0], t[1], t[2]);
}

/*********************************************************************/

hsa_status_t print_pool_callback(hsa_amd_memory_pool_t memory_pool, void* data)
{
  hsa_agent_t agent;
  agent.handle = (uint64_t)data;

  printf("\n    \n     ########  Mem pool  #######\n\n");

  hsa_amd_segment_t seg;
  hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_SEGMENT, &seg);
  const char* segm = (seg == HSA_AMD_SEGMENT_GLOBAL ? "Global" :
                     (seg == HSA_AMD_SEGMENT_GROUP ? "Group" :
                     (seg == HSA_AMD_SEGMENT_PRIVATE ? "Private" :
                     (seg == HSA_AMD_SEGMENT_READONLY ? "Readonly" : "Unknown" ))));
  printf("      %-24s  %s\n", "Segment:", segm);

  size_t size;
  hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_SIZE, &size);
  printf("      %-24s  %zu\n", "Size:", size);

  hsa_amd_memory_pool_global_flag_t flags;
  hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS, &flags);
  const char* coarse = flags & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_COARSE_GRAINED ? "Coarse" : "";
  const char* fine = flags & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED ? "Fine" : "";
  const char* kernarg = flags & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_KERNARG_INIT ? "KernArg" : "";
  printf("      %-24s  %s %s %s\n", "Flags:", coarse, fine, kernarg);

  char bolret;
  hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_ACCESSIBLE_BY_ALL, &bolret);
  printf("      %-24s  %s\n", "Accessible by all:", (bolret ? "yes" : "no"));

  hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALLOWED, &bolret);
  printf("      %-24s  %s\n", "Allows runtime alloc:", (bolret ? "yes" : "no"));

  if (bolret)
    {
      size_t gran, align;
      hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_GRANULE, &gran);
      printf("      %-24s  %zu\n", "Granularity:", gran);

      hsa_amd_memory_pool_get_info(memory_pool, HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALIGNMENT, &align);
      printf("      %-24s  %zu\n", "Alignment:", align);


    }

  hsa_amd_memory_pool_access_t acc;
  hsa_amd_memory_pool_link_info_t info;

  HSA_CHECK(hsa_amd_agent_memory_pool_get_info(agent, memory_pool, HSA_AMD_AGENT_MEMORY_POOL_INFO_ACCESS, &acc));
  HSA_CHECK(hsa_amd_agent_memory_pool_get_info(agent, memory_pool, HSA_AMD_AGENT_MEMORY_POOL_INFO_LINK_INFO, &info));

  const char *access = (acc == HSA_AMD_MEMORY_POOL_ACCESS_NEVER_ALLOWED ? "Never" :
    (acc == HSA_AMD_MEMORY_POOL_ACCESS_ALLOWED_BY_DEFAULT ? "Allow by default" : "Disallow by default"));
  printf("      %-24s  %s\n", "Access: ", access);
  const char* link_type = (info.link_type == HSA_AMD_LINK_INFO_TYPE_PCIE ? "PCIE" :
  (info.link_type == HSA_AMD_LINK_INFO_TYPE_QPI ? "QPI" : "Hypertransport"));
  printf("      %-24s  %s\n", "Link type: ", link_type);

  printf("      %-24s  %u ns\n", "Min latency:", info.min_latency);
  printf("      %-24s  %u ns\n", "Max latency:", info.max_latency);
  printf("      %-24s  %u MB/s\n", "Min bandwidth:", info.min_bandwidth);
  printf("      %-24s  %u MB/s\n", "Max bandwidth:", info.max_bandwidth);

  return HSA_STATUS_SUCCESS;
}

/*********************************************************************/

int main(int argc, char** argv)
{
  HSA_CHECK(hsa_init());

  HSA_CHECK(hsa_iterate_agents(hsa_get_agents_callback, NULL));

  printf("\nFound %d agents.\n", found_hsa_agents);

  unsigned i;
  for(i=0; i<found_hsa_agents; i++)
  {

  hsa_agent_t agent = hsa_agents[i];
  printf("\n\n  Agent %u:\n", i);

  GET_AGENT_INFO_STR(NAME, "Device Name", name_t, "%s");
  GET_AGENT_INFO_STR(VENDOR_NAME, "Vendor Name", name_t, "%s");
  GET_AGENT_INFO_ENUM(DEVICE, "Device Type:", hsa_device_type_t, print_type);
  GET_AGENT_INFO_ENUM(FEATURE, "Device Role ", hsa_agent_feature_t, print_role);
  GET_AGENT_INFO_ENUM(MACHINE_MODEL, "Device Machine Model ",  hsa_machine_model_t, print_model);
  GET_AGENT_INFO_ENUM(PROFILE, "Device Profile ", hsa_profile_t, print_profile);
  // kernel agent
  GET_AGENT_INFO(FAST_F16_OPERATION, "Fast F16 ops ", uint8_t, "%hhu");
  GET_AGENT_INFO(WAVEFRONT_SIZE, "Wavefront size ", uint32_t, "%u");
  GET_AGENT_INFO_ARRAY(WORKGROUP_MAX_DIM, wg_dim3_t, print_wg_sizes);
  GET_AGENT_INFO(WORKGROUP_MAX_SIZE, "WG max size ", uint32_t, "%u");
  GET_AGENT_INFO_STRUCT(GRID_MAX_DIM, hsa_dim3_t, print_grid_sizes);
  GET_AGENT_INFO(GRID_MAX_SIZE, "Grid max size ", uint32_t, "%u");
  GET_AGENT_INFO(QUEUES_MAX, "Max Queues ", uint32_t, "%u");
  GET_AGENT_INFO(QUEUE_MIN_SIZE, "Queue min size", uint32_t, "%u");
  GET_AGENT_INFO(QUEUE_MAX_SIZE, "Queue max size", uint32_t, "%u");
  GET_AGENT_INFO_ENUM(QUEUE_TYPE, "Queue type", hsa_queue_type_t, print_queue_type);
  GET_AGENT_INFO_ARRAY(CACHE_SIZE, cache_size_t, print_cache_sizes);

  GET_AGENT_INFO(VERSION_MAJOR, "HSA Runtime supported version (major):", uint16_t, "%hu");
  GET_AGENT_INFO(VERSION_MINOR, "HSA Runtime supported version (minor):", uint16_t, "%hu");


  printf("\n    ########  AMD SPECIFIC  #########################################\n\n");

  AMD_GET_AGENT_INFO(CHIP_ID, "Chip ID:", uint32_t, "0x%X");
  AMD_GET_AGENT_INFO(CACHELINE_SIZE, "Cacheline size:", uint32_t, "%u");
  AMD_GET_AGENT_INFO(COMPUTE_UNIT_COUNT, "CU count:", uint32_t, "%u");
  AMD_GET_AGENT_INFO(MAX_CLOCK_FREQUENCY, "Max clock:", uint32_t, "%u MHz");
  AMD_GET_AGENT_INFO(MAX_ADDRESS_WATCH_POINTS, "Max Watchpoints:", uint32_t, "%u");
  AMD_GET_AGENT_INFO(MEMORY_WIDTH, "Memory width:", uint32_t, "%u bits");
  AMD_GET_AGENT_INFO(MEMORY_MAX_FREQUENCY, "Memory freq:", uint32_t, "%u MHz");

  HSA_CHECK(hsa_amd_agent_iterate_memory_pools(agent, print_pool_callback, (void*)agent.handle));

  printf("\n    #################################################################\n\n\n");
  }

}
