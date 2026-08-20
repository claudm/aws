# aws
O problema é que a coluna da esquerda tem label + input + nota, e a .sap-form-note aumenta a altura da coluna. Como o align-items-end alinha pelo rodapé, o botão desce até a base da nota em vez de ficar na linha do input.

A solução é alinhar a linha pelo topo e colocar um label "fantasma" na coluna do botão, para ele nascer na mesma altura do campo.

Linha do 2FA (735–748):

html
<div class="form-row align-items-start">
  <div class="form-group col-lg-8">
    <label for="sap_pentest_direct_totp_secret" class="mb-1 small">2FA - optional</label>
    <input type="text" class="form-control form-control-sm" id="sap_pentest_direct_totp_secret" placeholder="Enter TOTP secret manually or upload QR code" disabled>
    <div class="sap-form-note">Provide your TOTP secret for 2FA-protected apps.</div>
  </div>
  <div class="form-group col-lg-4">
    <label class="mb-1 small invisible d-none d-lg-block">&nbsp;</label>
    <input type="file" class="d-none" id="sap_pentest_qr_file" accept="image/*" disabled>
    <button type="button" class="btn btn-sm btn-outline-secondary w-100" id="sapBtnUploadQrCode" disabled>Upload QR code</button>
    <div id="sapPentestQrUploadStatus" class="small text-muted mt-2"></div>
  </div>
</div>

Linha do Access URL (750–761):

html
<div class="form-row align-items-start">
  <div class="form-group col-lg-10">
    <label for="sap_pentest_access_url" class="mb-1 small">Access URL</label>
    <select class="form-control form-control-sm" id="sap_pentest_access_url" disabled>
      <option value="">Select target URL</option>
    </select>
    <div class="sap-form-note">Select which URL will be utilizing this credential.</div>
  </div>
  <div class="form-group col-lg-2">
    <label class="mb-1 small invisible d-none d-lg-block">&nbsp;</label>
    <button type="button" class="btn btn-sm btn-outline-secondary w-100" id="sapBtnClearAccessUrl" disabled>Clear</button>
  </div>
</div>

Pontos de atenção:

Tirei o wrapper div.w-100 — ele era necessário só por causa do d-flex, agora o .form-group já é flex-direction: column.
O d-none d-lg-block no label fantasma evita o espaço vazio no mobile, onde as colunas empilham.
Se o justify-content: flex-end do seu .form-group atrapalhar, adicione no CSS:
css
.form-row.align-items-start > .form-group {
  justify-content: flex-start;
}
