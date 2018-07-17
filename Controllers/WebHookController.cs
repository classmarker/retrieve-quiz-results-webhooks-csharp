using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Http;

namespace cSharp.Controllers
{
    public class WebHookController : ApiController
    {
        private string SECRET_KEY = "your api secret here";

        [HttpPost]
        [Route("webhook")]
        public async Task<IHttpActionResult> ProcessWebHook()
        {
            var payloadJson = await Request.Content.ReadAsStringAsync();

            if (!await PayloadSignatureMatchesHeader(payloadJson))
            {
                return Unauthorized();
            }

            if (payloadJson == null)
            {
                return BadRequest("Invalid object");
            }

            // Save results in your database.
            // Important: Do not use a script that will take a long time to respond.

            return Ok();

        }

        private async Task<bool> PayloadSignatureMatchesHeader(string payloadJson)
        {
            var hashFromHeader = Request.Headers.GetValues("X-Classmarker-Hmac-Sha256").FirstOrDefault();
            var hashFromPayload = GenerateSHA256FromPayload(payloadJson);
            return hashFromPayload == hashFromHeader;
        }

        private string GenerateSHA256FromPayload(string payloadJson)
        {
            var encoding = new System.Text.ASCIIEncoding();
            var keyByte = encoding.GetBytes(SECRET_KEY);
            var payloadBytes = encoding.GetBytes(payloadJson);

            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                var hashmessage = hmacsha256.ComputeHash(payloadBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

    }
}
