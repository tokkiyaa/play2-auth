package jp.t2v.lab.play2.auth

import jp.t2v.lab.play2.auth.crypto.Signer
import play.api.mvc.{RequestHeader, Result}

trait TokenAccessor {

  def extract(request: RequestHeader): Option[AuthenticityToken]

  def put(token: AuthenticityToken)(result: Result)(implicit request: RequestHeader): Result

  def delete(result: Result)(implicit request: RequestHeader): Result

  protected def sign(token: AuthenticityToken): SignedToken = Signer.sign(token) + token

  protected def verifyHmac(token: SignedToken): Option[AuthenticityToken] = {
    val (hmac, value) = token.splitAt(40)
    if (Signer.verify(hmac, value)) Some(value) else None
  }

}
