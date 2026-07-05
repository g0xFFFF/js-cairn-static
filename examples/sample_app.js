const BASE = "/api";
const api = {
  updateUser: BASE + "/user/update",
  orderDetail: "/api/order/detail",
};

function request(config) {
  config.headers = {
    Authorization: localStorage.getItem("token"),
    "X-CSRF-Token": window.csrf,
  };
  return axios(config).then((r) => r.data);
}

const form = {
  nickname: input.value,
  role: route.query.role,
  isAdmin: false,
};

request({
  url: api.updateUser,
  method: "post",
  data: form,
});

axios.get(api.orderDetail, {
  params: {
    orderId: route.query.orderId,
    userId: route.query.userId,
  },
});

fetch(`/api/file/download/${fileId}?path=${path}`, {
  method: "POST",
  body: JSON.stringify({ filePath: route.query.path, tenantId: route.params.tenantId }),
});
